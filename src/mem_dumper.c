#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

enum
{
    Op_None,
    Op_DumpMemory,
    Op_CompareMemory,
};

static void *
ReadEntireFile(char *file_name, size_t *out_size)
{
    void *result = NULL;
    
    FILE *in = fopen(file_name, "rb");
    if (in)
    {
        fseek(in, 0, SEEK_END);
        *out_size = ftell(in);
        fseek(in, 0, SEEK_SET);
        
        result = malloc(*out_size);
        fread(result, *out_size, 1, in);
        fclose(in);
    }
    else
    {
        fprintf(stderr, "Unable to read file %s\n", file_name);
    }
    
    return result;
}

static char *
PathRemovedExtension(char *path)
{
    static char result[MAX_PATH]; // NOTE: Nasty 'ol local buffer return

    size_t last_period = 0;
    for (size_t i = 0; (i < MAX_PATH) && path[i]; ++i)
    {
        if (path[i] == '.')
        {
            last_period = i;
        }
    }

    memcpy(result, path, last_period);
    result[last_period] = 0;

    return result;
}

static bool
StringCompareInsensitive(char *a, char *b)
{
    bool result = (*a == *b); // NOTE: Account for zero length strings
    while (*a && *b)
    {
        if (tolower(*a) != tolower(*b))
        {
            result = false;
            break;
        }
        ++a;
        ++b;
    }
    return result;
}

static void
ReportLastError(void)
{
    DWORD error = GetLastError();
    char *message;
    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL, error, 0, (char *)&message, 0, NULL))
    {
        fprintf(stderr, "System Error: %s", message);
        LocalFree(message);
    }
    else
    {
        fprintf(stderr, "Look, mate, even the error reporting gave an error. What do you want from me.\n");
    }
}

static DWORD
FindProcessIDByName(char *name)
{
    DWORD result = 0;

    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (handle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process = { .dwSize = sizeof(PROCESSENTRY32) };
        if (Process32First(handle, &process))
        {
            do
            {
                char *path = process.szExeFile;
                char *path_no_extension = PathRemovedExtension(process.szExeFile);
                if (StringCompareInsensitive(name, path) ||
                    StringCompareInsensitive(name, path_no_extension))
                {
                    result = process.th32ProcessID;
                    break;
                }
            }
            while (Process32Next(handle, &process));
        }
    }
    else
    {
        fprintf(stderr, "Could not make toolhelp snapshot.\n");
    }
    CloseHandle(handle);

    return result;
}

int
main(int argc, char **argv)
{
    uint64_t target_process_id = 0;
    uint64_t starting_address = 0;
    uint64_t amount_to_read = 0;
    char *out_file_location = NULL;
    
    char *compare_file_a = NULL;
    char *compare_file_b = NULL;
    
    int op = Op_None;
    if (argc < 2)
    {
        fprintf(stderr, "Pass me some arguments, bro.\n");
    }
    else if (0 == strcmp(argv[1], "-dump"))
    {
        if (argc == 6)
        {
            op = Op_DumpMemory;
            
            char *target_process_id_str = argv[2];
            char *starting_address_str = argv[3];
            char *amount_to_read_str = argv[4];
            
            char *end;
            target_process_id = strtoull(target_process_id_str, &end, 0);
            if (end == target_process_id_str)
            {
                target_process_id = FindProcessIDByName(target_process_id_str);
            }
            starting_address = strtoull(starting_address_str, &end, 0);
            amount_to_read = strtoull(amount_to_read_str, &end, 0);
            
            out_file_location = argv[5];
        }
        else
        {
            fprintf(stderr, "Expected 4 arguments after -dump.\n");
        }
    }
    else if (0 == strcmp(argv[1], "-compare"))
    {
        if (argc == 4)
        {
            op = Op_CompareMemory;
            
            compare_file_a = argv[2];
            compare_file_b = argv[3];
        }
        else
        {
            fprintf(stderr, "Expected 2 arguments after -compare.\n");
        }
    }
    else
    {
        fprintf(stderr, "Unexpected arguments. I support -dump and -compare.\n");
    }
    
    if (op == Op_DumpMemory)
    {
        HANDLE process_handle = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION,
                                            FALSE,
                                            (DWORD)target_process_id);
        if (process_handle != INVALID_HANDLE_VALUE)
        {
            char process_path[MAX_PATH];
            if (GetModuleFileNameExA(process_handle, NULL, process_path, MAX_PATH))
            {
                fprintf(stderr, "Successfully opened process '%s' (PID: %llu)\n", process_path, target_process_id);
            }
            else
            {
                fprintf(stderr, "Cool, we opened the process handle, yet somehow we failed to get the process name.\n");
                ReportLastError();
            }

            fprintf(stderr, "Dumping %llu bytes from address %llu.\n", amount_to_read, starting_address);
            
            void *buffer = malloc(amount_to_read);
            
            const void *read_pointer = (const void *)starting_address;
            size_t amount_read;
            if (ReadProcessMemory(process_handle,
                                  read_pointer,
                                  buffer,
                                  (size_t)amount_to_read,
                                  &amount_read))
            {
                fprintf(stderr, "Successfully read process memory.\n");
                FILE *out_file = fopen(out_file_location, "wb");
                if (out_file)
                {
                    fwrite(buffer, amount_read, 1, out_file);
                    fprintf(stderr, "Dumped memory to %s.\n", out_file_location);
                }
                else
                {
                    fprintf(stderr, "Could not open '%s' for writing.\n", out_file_location);
                }
            }
            else
            {
                fprintf(stderr, "Could not read process memory.\n");
                ReportLastError();
            }
            CloseHandle(process_handle);
        }
        else
        {
            fprintf(stderr, "Could not open process handle with PID %llu.\n", target_process_id);
            ReportLastError();
        }
    }
    else if (op == Op_CompareMemory)
    {
        size_t file_a_size;
        size_t file_b_size;
        void *file_a = ReadEntireFile(compare_file_a, &file_a_size);
        void *file_b = ReadEntireFile(compare_file_b, &file_b_size);
        
        if (file_a && file_b)
        {
            if (file_a_size == file_b_size)
            {
                bool are_equal = (0 == memcmp(file_a, file_b, file_a_size));
                if (are_equal)
                {
                    printf("Yes, these files are the same.\n");
                }
                else
                {
                    printf("No, these files are not the same.\n");
                }
            }
            else
            {
                fprintf(stderr, "Files are not the same size, A is %zu bytes but B is %zu bytes.\n",
                        file_a_size,
                        file_b_size);
            }
        }
        else
        {
            if (!file_a) fprintf(stderr, "Could not open '%s' for reading.\n", compare_file_a);
            if (!file_b) fprintf(stderr, "Could not open '%s' for reading.\n", compare_file_b);
        }
    }
    else
    {
        fprintf(stderr, "No operation specified.\n");
    }
    
    return 0;
}

