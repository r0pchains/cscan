#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>

#define BUFFER_SIZE 1024
#define TARGET_EXT ".c"

// ANSI escape codes for colored output
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

// Function to check for potential buffer overflow vulnerabilities
void check_buffer_overflow(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    const char *vulnerable_functions[] = {
        "strcpy(",
        "strcat(",
        "sprintf(",
        "gets(",
        "scanf(",
        "fgets("
    };
    size_t num_functions = sizeof(vulnerable_functions) / sizeof(vulnerable_functions[0]);
    bool found_vuln = false;
    char *found_funcs[num_functions];
    size_t found_count = 0;

    while (fgets(buffer, BUFFER_SIZE, file)) {
        for (size_t i = 0; i < num_functions; i++) {
            if (strstr(buffer, vulnerable_functions[i])) {
                // Check if the function was already noted
                bool already_found = false;
                for (size_t j = 0; j < found_count; j++) {
                    if (strcmp(found_funcs[j], vulnerable_functions[i]) == 0) {
                        already_found = true;
                        break;
                    }
                }
                // If not already noted, add it
                if (!already_found) {
                    found_funcs[found_count++] = (char *)vulnerable_functions[i];
                }
                found_vuln = true;
            }
        }
    }

    if (found_vuln) {
        printf("Potential buffer overflow vulnerability found in: %s\n", filename);
        for (size_t i = 0; i < found_count; i++) {
            printf(COLOR_RED "  - Found vulnerable function: %s" COLOR_RESET "\n", found_funcs[i]);
        }
    }

    fclose(file);
}

// Function to scan a directory for C source code files
void scan_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;

    if (!dir) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Construct the full path for the file
        char full_path[BUFFER_SIZE];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // Check if it's a directory or a file
        if (entry->d_type == DT_DIR) {
            // Ignore the "." and ".." directories
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Recursively scan the subdirectory
                scan_directory(full_path);
            }
        } else if (entry->d_type == DT_REG) {
            // Check if it's a C source file
            if (strstr(entry->d_name, TARGET_EXT)) {
                // Check for potential buffer overflow vulnerabilities in the C file
                check_buffer_overflow(full_path);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    scan_directory(argv[1]);
    return EXIT_SUCCESS;
}
