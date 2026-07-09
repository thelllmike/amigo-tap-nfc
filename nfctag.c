/*
 * nfctag — read / write / dump NDEF on MIFARE Classic 1K tags
 *          using an ACS ACR122U (or any PC/SC CCID reader) on macOS.
 *
 * Build:  make           (or: cc -O2 -o nfctag nfctag.c -framework PCSC)
 * Usage:  ./nfctag read
 *         ./nfctag write "https://example.com/foo"
 *         ./nfctag write --text "hello world"
 *         ./nfctag dump
 *
 * Writing auto-NDEF-formats a blank tag (writes the MAD directory in sector 0
 * and switches data-sector keys to the NDEF key D3F7D3F7D3F7). It is idempotent:
 * re-running on an already-formatted tag just rewrites the message. Tags written
 * this way read on both Android and iPhone.
 */
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ---- URI prefix abbreviations (NFC Forum URI RTD) ---- */
static const char *URI_PREFIX[] = {
  "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
  "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://",
  "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://",
  "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
  "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
  "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:"
};
#define N_URI_PREFIX (int)(sizeof(URI_PREFIX)/sizeof(URI_PREFIX[0]))

/* ---- MIFARE Classic constants ---- */
static const BYTE KEY_FF[6]   = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const BYTE KEY_NDEF[6] = {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7};
static const BYTE KEY_MAD[6]  = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5};
static const BYTE MAD_TRAILER[16]  = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5, 0x78,0x77,0x88,0xC1, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const BYTE NDEF_TRAILER[16] = {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7, 0x7F,0x07,0x88,0x40, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

static SCARDCONTEXT g_ctx;
static SCARDHANDLE  g_card;
static SCARD_IO_REQUEST g_pci;

/* ---- low-level helpers ---- */
static int transmit(const BYTE *cmd, int clen, BYTE *out, DWORD *olen){
  *olen = 300;
  return SCardTransmit(g_card, &g_pci, cmd, clen, NULL, out, olen) == 0;
}
static int sw_ok(const BYTE *o, DWORD ol){ return ol>=2 && o[ol-2]==0x90 && o[ol-1]==0x00; }

static int auth(int block, const BYTE *key){          /* key A */
  BYTE o[300]; DWORD ol;
  BYTE load[]={0xFF,0x82,0x00,0x00,0x06, key[0],key[1],key[2],key[3],key[4],key[5]};
  if(!transmit(load,sizeof(load),o,&ol)||!sw_ok(o,ol)) return 0;
  BYTE a[]={0xFF,0x86,0x00,0x00,0x05, 0x01,0x00,(BYTE)block,0x60,0x00};
  return transmit(a,sizeof(a),o,&ol) && sw_ok(o,ol);
}
static int read_block(int block, BYTE *dst){
  BYTE o[300]; DWORD ol; BYTE r[]={0xFF,0xB0,0x00,(BYTE)block,0x10};
  if(!transmit(r,sizeof(r),o,&ol) || ol<18 || o[ol-2]!=0x90) return 0;
  memcpy(dst,o,16); return 1;
}
static int write_block(int block, const BYTE *data){
  BYTE o[300]; DWORD ol; BYTE w[21]={0xFF,0xD6,0x00,(BYTE)block,0x10};
  memcpy(w+5,data,16);
  if(!transmit(w,sizeof(w),o,&ol) || !sw_ok(o,ol)){
    fprintf(stderr,"  ! write block %d failed (SW=%02X%02X)\n",block,
            ol>=2?o[ol-2]:0, ol>=2?o[ol-1]:0);
    return 0;
  }
  return 1;
}
static BYTE mad_crc(const BYTE *d, int len){          /* CRC-8/MIFARE-MAD */
  BYTE crc=0xC7;
  for(int i=0;i<len;i++){ crc^=d[i]; for(int b=0;b<8;b++) crc=(crc&0x80)?(crc<<1)^0x1D:(crc<<1); }
  return crc;
}

/* ---- connect / disconnect ---- */
static int connect_reader(void){
  if(SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&g_ctx)){ fprintf(stderr,"PC/SC unavailable.\n"); return 0; }
  DWORD len=0;
  if(SCardListReaders(g_ctx,NULL,NULL,&len)){ fprintf(stderr,"No reader found. Is the ACR122U plugged in?\n"); return 0; }
  char *rs=calloc(1,len); SCardListReaders(g_ctx,NULL,rs,&len);
  DWORD proto;
  LONG rv=SCardConnect(g_ctx,rs,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,&g_card,&proto);
  free(rs);
  if(rv){ fprintf(stderr,"No tag on the reader. Place a tag and try again.\n"); return 0; }
  g_pci=(proto==SCARD_PROTOCOL_T1)?*SCARD_PCI_T1:*SCARD_PCI_T0;
  return 1;
}
static void disconnect_reader(void){ SCardDisconnect(g_card,SCARD_LEAVE_CARD); SCardReleaseContext(g_ctx); }

/* ---- build an NDEF message (URI or Text) ---- */
static int build_ndef(const char *val, int as_text, BYTE *out){
  BYTE payload[900]; int plen=0; BYTE type;
  if(as_text){
    type='T';
    const char *lang="en";
    payload[plen++]=(BYTE)strlen(lang);         /* status: UTF-8, lang length */
    memcpy(payload+plen,lang,strlen(lang)); plen+=strlen(lang);
    int vl=strlen(val); memcpy(payload+plen,val,vl); plen+=vl;
  } else {
    type='U';
    int best=0; size_t bestlen=0;
    for(int i=1;i<N_URI_PREFIX;i++){                /* longest matching prefix wins */
      size_t l=strlen(URI_PREFIX[i]);
      if(l>bestlen && strncmp(val,URI_PREFIX[i],l)==0){ best=i; bestlen=l; }
    }
    payload[plen++]=(BYTE)best;
    const char *rest=val+bestlen; int rl=strlen(rest);
    memcpy(payload+plen,rest,rl); plen+=rl;
  }
  int n=0;
  int sr = (plen<=255);
  out[n++]= (0xC0) | (sr?0x10:0x00) | 0x01;        /* MB=1 ME=1 [SR] TNF=001 */
  out[n++]= 0x01;                                   /* type length */
  if(sr){ out[n++]=(BYTE)plen; }
  else  { out[n++]=(plen>>24)&0xFF; out[n++]=(plen>>16)&0xFF; out[n++]=(plen>>8)&0xFF; out[n++]=plen&0xFF; }
  out[n++]=type;
  memcpy(out+n,payload,plen); n+=plen;
  return n;
}

/* Data-block layout: sectors 1..15, 3 data blocks each (trailers skipped).
   Logical block k (0..44) -> physical block (1+k/3)*4 + k%3. */

/* ================= commands ================= */

static void parse_ndef(BYTE *mem, int mlen){
  int i=0, found=0;
  while(i<mlen){
    BYTE tag=mem[i];
    if(tag==0x00){ i++; continue; }
    if(tag==0xFE) break;
    if(i+1>=mlen) break;
    int L=mem[i+1], hdr=2;
    if(L==0xFF){ if(i+3>=mlen) break; L=(mem[i+2]<<8)|mem[i+3]; hdr=4; }
    if(tag==0x03){
      int p=i+hdr, end=i+hdr+L; if(end>mlen) end=mlen; int rec=0;
      while(p<end){
        BYTE fl=mem[p], tnf=fl&0x07, tl=mem[p+1]; int off=p+2; long pl;
        if(fl&0x10){ pl=mem[off]; off+=1; }
        else { pl=((long)mem[off]<<24)|(mem[off+1]<<16)|(mem[off+2]<<8)|mem[off+3]; off+=4; }
        if(fl&0x08) off+=1;
        BYTE *ty=mem+off; off+=tl; BYTE *pay=mem+off;
        found=1;
        printf("  record %d: TNF=%d type='%.*s'\n",++rec,tnf,tl,ty);
        if(tnf==1 && tl==1 && ty[0]=='U'){
          int c=pay[0]; const char *pre=(c<N_URI_PREFIX)?URI_PREFIX[c]:"";
          printf("    URI:  %s%.*s\n",pre,(int)pl-1,pay+1);
        } else if(tnf==1 && tl==1 && ty[0]=='T'){
          int ll=pay[0]&0x3F;
          printf("    Text: %.*s\n",(int)pl-1-ll,pay+1+ll);
        } else {
          printf("    payload (%ld bytes): ",pl);
          for(long k=0;k<pl&&k<64;k++) printf("%02X",pay[k]); printf("\n");
        }
        off+=pl; p=off; if(fl&0x40) break;
      }
    }
    i+=hdr+L;
  }
  if(!found) printf("  (no NDEF record found — tag is blank or not NDEF-formatted)\n");
}

static int cmd_read(void){
  if(!connect_reader()) return 1;
  BYTE uid[300]; DWORD ul; BYTE gu[]={0xFF,0xCA,0x00,0x00,0x00};
  if(transmit(gu,sizeof(gu),uid,&ul)&&ul>=2){
    printf("UID: "); for(DWORD i=0;i+2<=ul;i++) printf("%02X",uid[i]); printf("\n");
  }
  BYTE mem[45*16]; int mlen=0, sectors=0;
  for(int sec=1;sec<16;sec++){
    int base=sec*4;
    if(!(auth(base,KEY_NDEF)||auth(base,KEY_FF)||auth(base,KEY_MAD))) continue;
    sectors++;
    for(int b=0;b<3;b++){ BYTE buf[16]; if(read_block(base+b,buf)){ memcpy(mem+mlen,buf,16); mlen+=16; } }
  }
  printf("Read %d data sectors (%d bytes).\n\n", sectors, mlen);
  parse_ndef(mem,mlen);
  disconnect_reader();
  return 0;
}

static int cmd_dump(void){
  if(!connect_reader()) return 1;
  for(int sec=0;sec<16;sec++){
    int base=sec*4; const char *k="---";
    if(auth(base,KEY_NDEF)) k="NDEF"; else if(auth(base,KEY_MAD)) k="MAD "; else if(auth(base,KEY_FF)) k="FFFF";
    printf("S%02d[%s] ",sec,k);
    for(int b=0;b<4;b++){ BYTE buf[16];
      if(read_block(base+b,buf)){ for(int j=0;j<16;j++) printf("%02X",buf[j]); printf(b<3?" ":""); }
      else printf("<locked>        ");
    }
    printf("\n");
  }
  disconnect_reader();
  return 0;
}

static int cmd_write(const char *val, int as_text){
  BYTE ndef[900]; int nlen=build_ndef(val,as_text,ndef);

  /* wrap in NDEF-message TLV + terminator */
  BYTE area[45*16]; memset(area,0,sizeof(area)); int t=0;
  area[t++]=0x03;
  if(nlen<0xFF){ area[t++]=(BYTE)nlen; }
  else { area[t++]=0xFF; area[t++]=(nlen>>8)&0xFF; area[t++]=nlen&0xFF; }
  if(t+nlen+1 > (int)sizeof(area)){ fprintf(stderr,"Message too big for a 1K tag (max ~%d bytes).\n",(int)sizeof(area)-4); return 1; }
  memcpy(area+t,ndef,nlen); t+=nlen; area[t++]=0xFE;

  printf("Encoding %s record, %d-byte NDEF message.\n", as_text?"Text":"URI", nlen);

  if(!connect_reader()) return 1;

  /* MAD (all data sectors flagged NDEF, AID 0x03E1) */
  BYTE mad[32]; memset(mad,0,sizeof(mad)); mad[1]=0x01;
  for(int s=0;s<15;s++){ mad[2+s*2]=0x03; mad[2+s*2+1]=0xE1; }
  mad[0]=mad_crc(mad+1,31);

  int fails=0, formatted=0;
  /* data sectors 1..15 */
  for(int sec=1;sec<16;sec++){
    int base=sec*4;
    int fresh=0;
    if(!auth(base,KEY_NDEF)){                 /* not yet NDEF-formatted */
      if(!auth(base,KEY_FF)){ fprintf(stderr,"  ! sector %d: unknown key, cannot write\n",sec); fails++; continue; }
      fresh=1;
    }
    for(int bi=0;bi<3;bi++){ int k=(sec-1)*3+bi; if(!write_block(base+bi,area+k*16)) fails++; }
    if(fresh){ if(!write_block(base+3,NDEF_TRAILER)) fails++; else formatted++; }
  }
  /* sector 0: MAD */
  int s0_fresh=0;
  if(!auth(0,KEY_MAD)){ if(auth(0,KEY_FF)) s0_fresh=1; else { fprintf(stderr,"  ! sector 0: unknown key\n"); fails++; } }
  if(auth(0,KEY_MAD)||auth(0,KEY_FF)){
    if(!write_block(1,mad))    fails++;
    if(!write_block(2,mad+16)) fails++;
    if(s0_fresh){ if(!write_block(3,MAD_TRAILER)) fails++; }
  }

  if(formatted) printf("Formatted %d blank sector(s) for NDEF.\n", formatted);
  if(fails){ fprintf(stderr,"\n%d block(s) failed to write.\n",fails); disconnect_reader(); return 1; }

  /* verify: re-read */
  BYTE mem[45*16]; int mlen=0;
  for(int sec=1;sec<16;sec++){ int base=sec*4;
    if(!auth(base,KEY_NDEF)) continue;
    for(int b=0;b<3;b++){ BYTE buf[16]; if(read_block(base+b,buf)){ memcpy(mem+mlen,buf,16); mlen+=16; } }
  }
  printf("\nWritten OK. Verify:\n");
  parse_ndef(mem,mlen);
  disconnect_reader();
  return 0;
}

static void usage(const char *p){
  printf("nfctag — read/write NDEF on MIFARE Classic 1K via ACR122U\n\n"
         "Usage:\n"
         "  %s read                 read & parse the tag on the reader\n"
         "  %s write <url>          format (if needed) and write a URI record\n"
         "  %s write --text <text>  write a plain-text record\n"
         "  %s dump                 hex-dump every sector\n", p,p,p,p);
}

int main(int argc, char **argv){
  if(argc<2){ usage(argv[0]); return 2; }
  if(!strcmp(argv[1],"read"))  return cmd_read();
  if(!strcmp(argv[1],"dump"))  return cmd_dump();
  if(!strcmp(argv[1],"write")){
    if(argc>=4 && (!strcmp(argv[2],"--text")||!strcmp(argv[2],"-t"))) return cmd_write(argv[3],1);
    if(argc>=3) return cmd_write(argv[2],0);
    fprintf(stderr,"write needs a value.\n"); return 2;
  }
  usage(argv[0]); return 2;
}
