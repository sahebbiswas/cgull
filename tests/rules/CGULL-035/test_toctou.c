#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

void test_access_open_vulnerable(const char *filepath) {
    if (access(filepath, R_OK) == 0) {
        int fd = open(filepath, O_RDONLY); // expect: CGULL-035
        if (fd >= 0) {
            close(fd);
        }
    }
}

void test_stat_fopen_vulnerable(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        FILE *fp = fopen(filepath, "r"); // expect: CGULL-035
        if (fp) {
            fclose(fp);
        }
    }
}

void test_lstat_unlink_vulnerable(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        unlink(path); // expect: CGULL-035
    }
}

void test_faccessat_chmod_vulnerable(const char *filename) {
    if (faccessat(AT_FDCWD, filename, F_OK, 0) == 0) {
        chmod(filename, 0644); // expect: CGULL-035
    }
}

void test_toctou_safe_remediated(const char *filepath) {
    // Remediation: open file directly, then check status on descriptor
    int fd = open(filepath, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            // Safe: descriptor operation
        }
        close(fd);
    }
}

void test_different_paths_safe(const char *file1, const char *file2) {
    if (access(file1, R_OK) == 0) {
        int fd = open(file2, O_RDONLY); // Different path, not TOCTOU
        if (fd >= 0) close(fd);
    }
}

void test_reassigned_path_safe(const char *initial_path) {
    const char *p = initial_path;
    if (access(p, R_OK) == 0) {
        p = "/tmp/other_file";
        int fd = open(p, O_RDONLY); // Reassigned, not TOCTOU
        if (fd >= 0) close(fd);
    }
}
