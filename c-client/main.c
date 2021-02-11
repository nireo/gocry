#include <dirent.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 4096

const char *root_dir_path = "./test";
const char *ransom_message = "You've been infected by gocry.\nAll your files are not encrypted\n";

int main() {
    DIR *root_dir = opendir(root_dir_path);
    struct dirent *dir;

    if (root_dir) {
        while ((dir = readdir(root_dir)) != NULL) {
            if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
                continue;
            }
            printf("%s\n", dir->d_name);
        }
        closedir(root_dir);
    }

    FILE *fp = fopen("./message.txt", "w+");
    if (fp) {
        fputs(ransom_message, fp);
    }
}
