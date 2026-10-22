#ifndef NFCCORE_H
#define NFCCORE_H
/* Read the NDEF tag on the reader; human-readable result written into log.
   Returns 0 on success, non-zero on error (message still in log). */
int amigo_read(char *log, int cap);
/* Format (if needed) and write value as a URI (as_text=0) or Text (as_text=1)
   record to the tag on the reader. Verifies by reading back. If lock is set and
   the tag is NTAG21x, it is then made permanently read-only (irreversible). */
int amigo_write(const char *value, int as_text, int lock, char *log, int cap);
#endif
