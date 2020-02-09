/*The python emoji decode and encode module.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char emojilable[] = {0xF0, 0x9F, 0x98, 0x9C, 0x00};
char emoji0[] = {0xF0, 0x9F, 0x98, 0x9A, 0x00};
char emoji1[] = {0xF0, 0x9F, 0x98, 0x81, 0x00};
char emoji2[] = {0xF0, 0x9F, 0x98, 0x82, 0X00};
char emoji3[] = {0xF0, 0x9F, 0x98, 0x83, 0X00};
char emoji4[] = {0xF0, 0x9F, 0x98, 0x84, 0X00};
char emoji5[] = {0xF0, 0x9F, 0x98, 0x85, 0X00};
char emoji6[] = {0xF0, 0x9F, 0x98, 0x86, 0X00};
char emoji7[] = {0xF0, 0x9F, 0x98, 0x89, 0X00};
char emoji8[] = {0xF0, 0x9F, 0x98, 0x8a, 0X00};
char emoji9[] = {0xF0, 0x9F, 0x98, 0x8b, 0X00};
char emojia[] = {0xF0, 0x9F, 0x98, 0x8c, 0X00};
char emojib[] = {0xF0, 0x9F, 0x98, 0x8d, 0X00};
char emojic[] = {0xF0, 0x9F, 0x98, 0x8f, 0X00};
char emojid[] = {0xF0, 0x9F, 0x98, 0x92, 0X00};
char emojie[] = {0xF0, 0x9F, 0x98, 0x93, 0X00};
char emojif[] = {0xF0, 0x9F, 0x98, 0x98, 0X00};

char semojilabel[] = "😜";
char semoji0[] = "😚";
char semoji1[] = "😁";
char semoji2[] = "😂";
char semoji3[] = "😃";
char semoji4[] = "😄";
char semoji5[] = "😅";
char semoji6[] = "😆";
char semoji7[] = "😉";
char semoji8[] = "😊";
char semoji9[] = "😋";
char semojia[] = "😌";
char semojib[] = "😍";
char semojic[] = "😏";
char semojid[] = "😒";
char semojie[] = "😓";
char semojif[] = "😘";

unsigned char *uemojilabel = (unsigned char *)semojilabel;
unsigned char *uemoji0 = (unsigned char *)semoji0;
unsigned char *uemoji1 = (unsigned char *)semoji1;
unsigned char *uemoji2 = (unsigned char *)semoji2;
unsigned char *uemoji3 = (unsigned char *)semoji3;
unsigned char *uemoji4 = (unsigned char *)semoji4;
unsigned char *uemoji5 = (unsigned char *)semoji5;
unsigned char *uemoji6 = (unsigned char *)semoji6;
unsigned char *uemoji7 = (unsigned char *)semoji7;
unsigned char *uemoji8 = (unsigned char *)semoji8;
unsigned char *uemoji9 = (unsigned char *)semoji9;
unsigned char *uemojia = (unsigned char *)semojia;
unsigned char *uemojib = (unsigned char *)semojib;
unsigned char *uemojic = (unsigned char *)semojic;
unsigned char *uemojid = (unsigned char *)semojid;
unsigned char *uemojie = (unsigned char *)semojie;
unsigned char *uemojif = (unsigned char *)semojif;