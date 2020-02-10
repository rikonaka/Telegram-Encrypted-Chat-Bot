#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libtecb.h"

static int detect_c(const char *input_str)
{
    /*
    detect the input_str is emoji encryption or not.

    return 1: detected.
    return 0: not detected.
    */

    unsigned char *input_bytes = (unsigned char *)input_str;
    int cursor;
    // int len = strlen(semojilabel);
    // printf("len: %d\n", len);
    // for (cursor = 0; cursor < 4; cursor ++)
    // only match the first code and last code now.
    for (cursor = 0; cursor < 4; cursor += 3)
    {
        //printf("input: %x\n", input_bytes[cursor]);
        //printf("emoji: %x\n", emojilable[cursor]);
        if (input_bytes[cursor] != uemojilabel[cursor])
        {
            return 0;
        }
    }
    return 1;
}


char *decode_c(const char *input_str)
{
    /*
    emoji-string to hex-string.
    */
    int cursor;
    int len;
    char *output_str;

    len = strlen(input_str);
    //printf("%d\n", len);
    output_str = (char *)malloc((len / 4) + 1);
    if (!output_str)
    {
        return NULL;
    }
    memset(output_str, 0, sizeof(char));
    unsigned char *input_bytes = (unsigned char *)input_str;
    for (cursor = 3; cursor < len; cursor += 4)
    {
        //printf("emoji: %x\n", input_bytes[cursor]);
        if (input_bytes[cursor] == uemoji0[3])
        {
            strcat(output_str, "0");
        }
        else if (input_bytes[cursor] == uemoji1[3])
        {
            strcat(output_str, "1");
        }
        else if (input_bytes[cursor] == uemoji2[3])
        {
            strcat(output_str, "2");
        }
        else if (input_bytes[cursor] == uemoji3[3])
        {
            strcat(output_str, "3");
        }
        else if (input_bytes[cursor] == uemoji4[3])
        {
            strcat(output_str, "4");
        }
        else if (input_bytes[cursor] == uemoji5[3])
        {
            strcat(output_str, "5");
        }
        else if (input_bytes[cursor] == uemoji6[3])
        {
            strcat(output_str, "6");
        }
        else if (input_bytes[cursor] == uemoji7[3])
        {
            strcat(output_str, "7");
        }
        else if (input_bytes[cursor] == uemoji8[3])
        {
            strcat(output_str, "8");
        }
        else if (input_bytes[cursor] == uemoji9[3])
        {
            strcat(output_str, "9");
        }
        else if (input_bytes[cursor] == uemojia[3])
        {
            strcat(output_str, "a");
        }
        else if (input_bytes[cursor] == uemojib[3])
        {
            strcat(output_str, "b");
        }
        else if (input_bytes[cursor] == uemojic[3])
        {
            strcat(output_str, "c");
        }
        else if (input_bytes[cursor] == uemojid[3])
        {
            strcat(output_str, "d");
        }
        else if (input_bytes[cursor] == uemojie[3])
        {
            strcat(output_str, "e");
        }
        else if (input_bytes[cursor] == uemojif[3])
        {
            strcat(output_str, "f");
        }
    }
    return output_str;
}

char *encode_c(const char *input_str)
{
    /*
    hex-string to emoji-string.
    */
    int cursor;
    int len;
    char *output_str;

    len = strlen(input_str);
    // one UTF-8 == 4 ASCII.
    // output_str = (char *)malloc(len * 4);
    output_str = (char *)malloc((len + 1) * 4);
    if (!output_str)
    {
        return NULL;
    }
    memset(output_str, 0, sizeof(char));

    strcat(output_str, emojilable);
    for (cursor = 0; cursor < len; cursor ++)
    {
        switch (input_str[cursor])
        {
            case '0':
                strcat(output_str, emoji0);
                break;
            
            case '1':
                strcat(output_str, emoji1);
                break;
            
            case '2':
                strcat(output_str, emoji2);
                break;
            
            case '3':
                strcat(output_str, emoji3);
                break;
            
            case '4':
                strcat(output_str, emoji4);
                break;
            
            case '5':
                strcat(output_str, emoji5);
                break;
            
            case '6':
                strcat(output_str, emoji6);
                break;
            
            case '7':
                strcat(output_str, emoji7);
                break;
            
            case '8':
                strcat(output_str, emoji8);
                break;
            
            case '9':
                strcat(output_str, emoji9);
                break;
            
            case 'a':
                strcat(output_str, emojia);
                break;
            
            case 'b':
                strcat(output_str, emojib);
                break;
            
            case 'c':
                strcat(output_str, emojic);
                break;
            
            case 'd':
                strcat(output_str, emojid);
                break;
            
            case 'e':
                strcat(output_str, emojie);
                break;
            
            case 'f':
                strcat(output_str, emojif);
                break;

            default:
                break;
        }
    }
    return output_str;
}

static PyObject *detect(PyObject *self, PyObject *args) {
    /*
    return 1: detect the emoji label.
    return 0: not detected.
    */
    const char *input_str;
    if (!PyArg_ParseTuple(args, "s", &input_str))
    {
        return NULL;
    }
    int ret = detect_c(input_str);
    if (!ret)
    {
        return Py_BuildValue("i", 0);
    }
    return Py_BuildValue("i", ret);
}

static PyObject *decode(PyObject *self, PyObject *args) {
    const char *input_str;
    char *output_str;

    if (!PyArg_ParseTuple(args, "s", &input_str))
    {
        return NULL;
    }
    output_str = decode_c(input_str);
    // Py_DECREF(output_str);
    if (!output_str)
    {
        free(output_str);
        return Py_BuildValue("s", "Emoji decode failed");
    }
    int output_str_len = strlen(output_str);
    char output_buff[output_str_len + 1];
    strcpy(output_buff, output_str);
    free(output_str);
    return Py_BuildValue("s", output_buff);
    // return Py_BuildValue("s", output_str);
}

static PyObject *encode(PyObject *self, PyObject *args) {
    const char *input_str;
    char *output_str;

    if (!PyArg_ParseTuple(args, "s", &input_str)) {
        return NULL;
    }

    output_str = encode_c(input_str);
    // Py_DECREF(output_str);
    if (!output_str)
    {
        free(output_str);
        return Py_BuildValue("s", "Emoji encode failed");
    }
    int output_str_len = strlen(output_str);
    char output_buff[output_str_len + 1];
    strcpy(output_buff, output_str);
    free(output_str);
    return Py_BuildValue("s", output_buff);
    //return Py_BuildValue("s", output_str);
}

/* Module method table */
static PyMethodDef LibtecbMethods[] = {
    {"decode",  decode, METH_VARARGS, "Decode emoji-string to string"},
    {"encode", encode, METH_VARARGS, "Encode string to emoji-string"},
    {"detect", detect, METH_VARARGS, "Detect the emoji encrytion label"},
    { NULL, NULL, 0, NULL}
};

/* Module structure */
static struct PyModuleDef libtecb = {
    PyModuleDef_HEAD_INIT,
    "libtecb",                                       /* name of module */
    "Using c to do something faster.",               /* Doc string (may be NULL) */
    -1,                                              /* Size of per-interpreter state or -1 */
    LibtecbMethods                                   /* Method table */
};

/* Module initialization function */
PyMODINIT_FUNC PyInit_libtecb(void) {
  return PyModule_Create(&libtecb);
}
