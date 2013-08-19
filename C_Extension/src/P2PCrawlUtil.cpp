#ifdef WIN32
#include <windows.h>
#endif

#include <Python.h> 
#include <stdio.h>

typedef unsigned char uint8;
typedef unsigned int uint32;

#ifdef WIN32 
BOOL APIENTRY
DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    return TRUE;
}
extern "C" __declspec(dllexport) PyObject * XorEncryptZeroAccess(PyObject *args)
#else
extern "C" PyObject * XorEncryptZeroAccess(PyObject *args)
#endif
{
	
    const char* buffer;
    //Py_ssize_t buffer_count;
	int buffer_count=0;
	PyObject * result;
    uint32 key=0;

	uint8 pre_buffer[2000]={0};
	   
	if (!PyArg_ParseTuple(args,"s#|i",&buffer,&buffer_count,&key))
	       return NULL;
	
	uint8* data_ptr = NULL;
	if(buffer_count > 2000)
			data_ptr = (uint8*)malloc(sizeof(uint8)*buffer_count);
	else
			data_ptr = pre_buffer;
	memcpy(data_ptr,buffer,buffer_count*sizeof(uint8));
	uint8* xor_key = (uint8*)&key;
    uint32 key_index = 0;
    uint32 len = 4;
	
    for(uint32 i=0;i<buffer_count;i++)    
    {
	
        *data_ptr = (*data_ptr) ^ (*(xor_key+key_index));
        data_ptr++;    
        key_index = (key_index+1)%len;
        if(key_index == 0)
        {
            key = (key<<1) | (key>>(32-1));
        }
    }

	result = Py_BuildValue("z#", pre_buffer, buffer_count);
	if(buffer_count > 2000)
		free(data_ptr);
	data_ptr = NULL;
	return result;
}
#ifdef WIN32
extern "C" __declspec(dllexport) int multiply(int num1, int num2)
#else
extern "C" int multiply(int num1, int num2)
#endif
{
    return num1 * num2;
}
