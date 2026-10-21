/* nfccore — MIFARE Classic 1K NDEF read/write over PC/SC (ACR122U).
 * Same logic as the nfctag CLI, but results go into a caller buffer so a GUI
 * can display them. Single-op-at-a-time (uses file-scope log cursor). */
#include "nfccore.h"
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static const char *URI_PREFIX[] = {
  "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
  "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://",
  "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://",
  "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
  "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
  "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:"
};
#define N_URI (int)(sizeof(URI_PREFIX)/sizeof(URI_PREFIX[0]))

static const BYTE KEY_FF[6]   = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const BYTE KEY_NDEF[6] = {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7};
static const BYTE KEY_MAD[6]  = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5};
static const BYTE MAD_TRAILER[16]  = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5, 0x78,0x77,0x88,0xC1, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const BYTE NDEF_TRAILER[16] = {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7, 0x7F,0x07,0x88,0x40, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

static SCARDCONTEXT g_ctx; static SCARDHANDLE g_card; static SCARD_IO_REQUEST g_pci;
static char *g_p, *g_end;

static void L(const char *fmt, ...){
  if(!g_p || g_p>=g_end) return;
  va_list ap; va_start(ap,fmt);
  int n=vsnprintf(g_p, g_end-g_p, fmt, ap); va_end(ap);
  if(n>0) g_p += (n < (g_end-g_p) ? n : (g_end-g_p-1));
}

static int transmit(const BYTE *cmd,int cl,BYTE *o,DWORD *ol){ *ol=300; return SCardTransmit(g_card,&g_pci,cmd,cl,NULL,o,ol)==0; }
static int sw_ok(const BYTE *o,DWORD ol){ return ol>=2 && o[ol-2]==0x90 && o[ol-1]==0x00; }

static int nauth(int blk,const BYTE *k){
  BYTE o[300]; DWORD ol;
  BYTE ld[]={0xFF,0x82,0,0,6,k[0],k[1],k[2],k[3],k[4],k[5]};
  if(!transmit(ld,sizeof(ld),o,&ol)||!sw_ok(o,ol)) return 0;
  BYTE a[]={0xFF,0x86,0,0,5,1,0,(BYTE)blk,0x60,0};
  return transmit(a,sizeof(a),o,&ol) && sw_ok(o,ol);
}
static int rblk(int blk,BYTE *d){ BYTE o[300]; DWORD ol; BYTE r[]={0xFF,0xB0,0,(BYTE)blk,0x10};
  if(!transmit(r,sizeof(r),o,&ol)||ol<18||o[ol-2]!=0x90) return 0; memcpy(d,o,16); return 1; }
static int wblk(int blk,const BYTE *d){ BYTE o[300]; DWORD ol; BYTE w[21]={0xFF,0xD6,0,(BYTE)blk,0x10};
  memcpy(w+5,d,16);
  if(!transmit(w,sizeof(w),o,&ol)||!sw_ok(o,ol)){ L("  ! write block %d failed (SW=%02X%02X)\n",blk,ol>=2?o[ol-2]:0,ol>=2?o[ol-1]:0); return 0; }
  return 1; }
static BYTE mad_crc(const BYTE *d,int len){ BYTE c=0xC7; for(int i=0;i<len;i++){ c^=d[i]; for(int b=0;b<8;b++) c=(c&0x80)?(c<<1)^0x1D:(c<<1);} return c; }

static int nconnect(void){
  if(SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&g_ctx)){ L("PC/SC unavailable.\n"); return 0; }
  DWORD len=0;
  if(SCardListReaders(g_ctx,NULL,NULL,&len)){ L("No reader found. Is the ACR122U plugged in?\n"); return 0; }
  char *rs=calloc(1,len); SCardListReaders(g_ctx,NULL,rs,&len);
  DWORD proto; LONG rv=SCardConnect(g_ctx,rs,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,&g_card,&proto);
  free(rs);
  if(rv){ L("No tag on the reader. Place a tag and try again.\n"); return 0; }
  g_pci=(proto==SCARD_PROTOCOL_T1)?*SCARD_PCI_T1:*SCARD_PCI_T0; return 1;
}
static void ndisconnect(void){ SCardDisconnect(g_card,SCARD_LEAVE_CARD); SCardReleaseContext(g_ctx); }

static int build_ndef(const char *val,int as_text,BYTE *out){
  BYTE pay[900]; int pl=0; BYTE type;
  if(as_text){ type='T'; const char *lang="en"; pay[pl++]=(BYTE)strlen(lang);
    memcpy(pay+pl,lang,strlen(lang)); pl+=strlen(lang);
    int vl=strlen(val); memcpy(pay+pl,val,vl); pl+=vl;
  } else { type='U'; int best=0; size_t bl=0;
    for(int i=1;i<N_URI;i++){ size_t l=strlen(URI_PREFIX[i]); if(l>bl && strncmp(val,URI_PREFIX[i],l)==0){best=i;bl=l;} }
    pay[pl++]=(BYTE)best; const char *r=val+bl; int rl=strlen(r); memcpy(pay+pl,r,rl); pl+=rl;
  }
  int n=0, sr=(pl<=255);
  out[n++]=0xC0|(sr?0x10:0)|0x01; out[n++]=0x01;
  if(sr) out[n++]=(BYTE)pl; else { out[n++]=(pl>>24)&0xFF;out[n++]=(pl>>16)&0xFF;out[n++]=(pl>>8)&0xFF;out[n++]=pl&0xFF; }
  out[n++]=type; memcpy(out+n,pay,pl); n+=pl; return n;
}

static void parse_ndef(BYTE *m,int ml){
  int i=0,found=0;
  while(i<ml){ BYTE tag=m[i];
    if(tag==0x00){i++;continue;} if(tag==0xFE) break; if(i+1>=ml) break;
    int Ln=m[i+1],hdr=2; if(Ln==0xFF){ if(i+3>=ml) break; Ln=(m[i+2]<<8)|m[i+3]; hdr=4; }
    if(tag==0x03){ int p=i+hdr,end=i+hdr+Ln; if(end>ml) end=ml;
      while(p<end){ BYTE fl=m[p],tnf=fl&7,tl=m[p+1]; int off=p+2; long pl;
        if(fl&0x10){pl=m[off];off+=1;} else {pl=((long)m[off]<<24)|(m[off+1]<<16)|(m[off+2]<<8)|m[off+3];off+=4;}
        if(fl&0x08) off+=1; BYTE *ty=m+off; off+=tl; BYTE *pa=m+off; found=1;
        if(tnf==1&&tl==1&&ty[0]=='U'){ int c=pa[0]; const char *pre=(c<N_URI)?URI_PREFIX[c]:"";
          L("  URI:  %s%.*s\n",pre,(int)pl-1,pa+1);
        } else if(tnf==1&&tl==1&&ty[0]=='T'){ int ll=pa[0]&0x3F; L("  Text: %.*s\n",(int)pl-1-ll,pa+1+ll);
        } else { L("  record TNF=%d, %ld bytes\n",tnf,pl); }
        off+=pl; p=off; if(fl&0x40) break;
      }
    }
    i+=hdr+Ln;
  }
  if(!found) L("  (no NDEF record — tag is blank or not NDEF-formatted)\n");
}

/* ---- NTAG21x (NFC Forum Type 2: NTAG213/215/216 coins, stickers, cards) ----
   4-byte pages, no keys. Page 3 = capability container (E1 10 <size/8> 00),
   NDEF TLV starts at page 4. */
static int is_ntag(void){
  BYTE atr[64]; DWORD al=sizeof(atr), st, pr, nl=0;
  if(SCardStatus(g_card,NULL,&nl,&st,&pr,atr,&al)) return 0;
  /* ACR122U ATR bytes 13-14 = PC/SC card name: 0001 Classic 1K, 0003 Ultralight/NTAG */
  return al>=15 && atr[13]==0x00 && atr[14]==0x03;
}
static int ntag_size(void){                       /* user memory bytes from GET_VERSION, 0 if unknown */
  BYTE o[300]; DWORD ol; BYTE gv[]={0xFF,0,0,0,3,0xD4,0x42,0x60};
  if(!transmit(gv,sizeof(gv),o,&ol)||ol<13||o[0]!=0xD5||o[2]!=0x00) return 0;
  switch(o[9]){ case 0x0F: L("Tag: NTAG213\n"); return 144;
                case 0x11: L("Tag: NTAG215\n"); return 504;
                case 0x13: L("Tag: NTAG216\n"); return 888; }
  return 0;
}
static int rpages(int pg,BYTE *d){ return rblk(pg,d); }   /* READ returns 4 pages (16 bytes) */
static int wpage(int pg,const BYTE *d){ BYTE o[300]; DWORD ol; BYTE w[9]={0xFF,0xD6,0,(BYTE)pg,4};
  memcpy(w+5,d,4);
  if(!transmit(w,sizeof(w),o,&ol)||!sw_ok(o,ol)){ L("  ! write page %d failed (SW=%02X%02X)\n",pg,ol>=2?o[ol-2]:0,ol>=2?o[ol-1]:0); return 0; }
  return 1; }
static int ntag_dump(BYTE *mem,int size){         /* read the user area (pages 4..) into mem */
  for(int off=0;off<size;off+=16){ if(!rpages(4+off/4,mem+off)) return 0; }
  return 1;
}

static int ntag_read(void){
  BYTE cc[16]; int size=ntag_size();
  if(!rpages(0,cc)){ L("Could not read tag.\n"); return 1; }
  if(cc[12]!=0xE1){ L("  (tag is not NDEF-formatted)\n"); return 0; }
  if(!size) size=cc[14]*8;
  BYTE mem[1024]; if(size>(int)sizeof(mem)-16) size=sizeof(mem)-16;
  if(!ntag_dump(mem,size)){ L("Read failed. Try re-seating the tag.\n"); return 1; }
  parse_ndef(mem,size); return 0;
}

static int ntag_write(const BYTE *ndef,int nl){
  BYTE cc[16]; int size=ntag_size();
  if(!rpages(0,cc)){ L("Could not read tag.\n"); return 1; }
  if(cc[12]==0x00 && cc[13]==0x00 && cc[14]==0x00 && cc[15]==0x00){   /* blank CC: format */
    if(!size){ L("Unknown tag size; cannot format.\n"); return 1; }
    BYTE ncc[4]={0xE1,0x10,(BYTE)(size/8),0x00};
    if(!wpage(3,ncc)) return 1; L("Formatted tag for NDEF.\n");
  } else if(cc[12]!=0xE1){ L("Tag has an unknown capability container; not writing.\n"); return 1; }
  else if(cc[15]!=0x00){ L("Tag is write-protected (locked).\n"); return 1; }
  else if(!size) size=cc[14]*8;

  BYTE area[1024]; memset(area,0,sizeof(area)); int t=0;
  area[t++]=0x03;
  if(nl<0xFF) area[t++]=(BYTE)nl; else { area[t++]=0xFF; area[t++]=(nl>>8)&0xFF; area[t++]=nl&0xFF; }
  if(t+nl+1>size){ L("Message too big for this tag (%d bytes max).\n",size-t-1); return 1; }
  memcpy(area+t,ndef,nl); t+=nl; area[t++]=0xFE;
  for(int i=0;i<t;i+=4) if(!wpage(4+i/4,area+i)){ L("\nWrite failed. Try re-seating the tag.\n"); return 1; }

  BYTE mem[1024]; int rl=(t+15)&~15;
  if(!ntag_dump(mem,rl)){ L("Written, but read-back failed.\n"); return 1; }
  L("\nDone. Verified on tag:\n");
  parse_ndef(mem,rl); return 0;
}

int amigo_read(char *log,int cap){
  g_p=log; g_end=log+cap; if(cap>0) log[0]=0;
  if(!nconnect()) return 1;
  BYTE uid[300]; DWORD ul; BYTE gu[]={0xFF,0xCA,0,0,0};
  if(transmit(gu,sizeof(gu),uid,&ul)&&ul>=2){ L("UID: "); for(DWORD i=0;i+2<=ul;i++) L("%02X",uid[i]); L("\n"); }
  if(is_ntag()){ int r=ntag_read(); ndisconnect(); return r; }
  BYTE mem[45*16]; int ml=0,sec_ok=0;
  for(int s=1;s<16;s++){ int base=s*4;
    if(!(nauth(base,KEY_NDEF)||nauth(base,KEY_FF)||nauth(base,KEY_MAD))) continue; sec_ok++;
    for(int b=0;b<3;b++){ BYTE buf[16]; if(rblk(base+b,buf)){ memcpy(mem+ml,buf,16); ml+=16; } }
  }
  L("Read %d data sectors.\n",sec_ok);
  parse_ndef(mem,ml);
  ndisconnect(); return 0;
}

int amigo_write(const char *value,int as_text,char *log,int cap){
  g_p=log; g_end=log+cap; if(cap>0) log[0]=0;
  if(!value||!value[0]){ L("Nothing to write — enter a link or text first.\n"); return 1; }
  if(strlen(value)>850){ L("Too long — max ~850 characters.\n"); return 1; }
  BYTE ndef[900]; int nl=build_ndef(value,as_text,ndef);
  L("Writing %s record (%d bytes)...\n", as_text?"text":"link", nl);
  if(!nconnect()) return 1;
  if(is_ntag()){ int r=ntag_write(ndef,nl); ndisconnect(); return r; }

  BYTE area[45*16]; memset(area,0,sizeof(area)); int t=0;
  area[t++]=0x03;
  if(nl<0xFF) area[t++]=(BYTE)nl; else { area[t++]=0xFF; area[t++]=(nl>>8)&0xFF; area[t++]=nl&0xFF; }
  if(t+nl+1 > (int)sizeof(area)){ L("Message too big for a 1K tag.\n"); ndisconnect(); return 1; }
  memcpy(area+t,ndef,nl); t+=nl; area[t++]=0xFE;

  BYTE mad[32]; memset(mad,0,sizeof(mad)); mad[1]=0x01;
  for(int s=0;s<15;s++){ mad[2+s*2]=0x03; mad[2+s*2+1]=0xE1; } mad[0]=mad_crc(mad+1,31);

  int fails=0,formatted=0;
  for(int s=1;s<16;s++){ int base=s*4,fresh=0;
    if(!nauth(base,KEY_NDEF)){ if(!nauth(base,KEY_FF)){ L("  ! sector %d locked with unknown key\n",s); fails++; continue; } fresh=1; }
    for(int bi=0;bi<3;bi++){ int k=(s-1)*3+bi; if(!wblk(base+bi,area+k*16)) fails++; }
    if(fresh){ if(!wblk(base+3,NDEF_TRAILER)) fails++; else formatted++; }
  }
  int s0f=0;
  if(!nauth(0,KEY_MAD)){ if(nauth(0,KEY_FF)) s0f=1; else { L("  ! sector 0 locked\n"); fails++; } }
  if(nauth(0,KEY_MAD)||nauth(0,KEY_FF)){
    if(!wblk(1,mad)) fails++; if(!wblk(2,mad+16)) fails++;
    if(s0f){ if(!wblk(3,MAD_TRAILER)) fails++; }
  }
  if(formatted) L("Formatted %d blank sector(s).\n",formatted);
  if(fails){ L("\n%d block(s) failed. Try re-seating the tag.\n",fails); ndisconnect(); return 1; }

  BYTE mem[45*16]; int ml=0;
  for(int s=1;s<16;s++){ int base=s*4; if(!nauth(base,KEY_NDEF)) continue;
    for(int b=0;b<3;b++){ BYTE buf[16]; if(rblk(base+b,buf)){ memcpy(mem+ml,buf,16); ml+=16; } } }
  L("\nDone. Verified on tag:\n");
  parse_ndef(mem,ml);
  ndisconnect(); return 0;
}
