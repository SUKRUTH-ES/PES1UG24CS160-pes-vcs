// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = NULL;
    char header[64];
    int header_len;
    size_t obj_len;
    unsigned char *obj_buf = NULL;
    char final_path[512];
    char shard_dir[512];
    char tmp_path[512];
    char *slash;
    int fd = -1;
    int dirfd = -1;
    ssize_t written_total = 0;

    switch (type) {
        case OBJ_BLOB: type_str = "blob"; break;
        case OBJ_TREE: type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len + 1 > sizeof(header)) {
        return -1;
    }
    header[header_len++] = '\0';

    obj_len = (size_t)header_len + len;
    obj_buf = malloc(obj_len);
    if (obj_buf == NULL) {
        return -1;
    }

    memcpy(obj_buf, header, (size_t)header_len);
    if (len > 0) {
        memcpy(obj_buf + header_len, data, len);
    }

    compute_hash(obj_buf, obj_len, id_out);
    if (object_exists(id_out)) {
        free(obj_buf);
        return 0;
    }

    object_path(id_out, final_path, sizeof(final_path));
    if (strlen(final_path) + strlen("/.tmpXXXXXX") + 1 > sizeof(tmp_path)) {
        free(obj_buf);
        return -1;
    }

    strncpy(shard_dir, final_path, sizeof(shard_dir) - 1);
    shard_dir[sizeof(shard_dir) - 1] = '\0';
    slash = strrchr(shard_dir, '/');
    if (slash == NULL) {
        free(obj_buf);
        return -1;
    }
    *slash = '\0';

    if (mkdir(shard_dir, 0755) < 0 && errno != EEXIST) {
        free(obj_buf);
        return -1;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s/.tmpXXXXXX", shard_dir);
    fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(obj_buf);
        return -1;
    }

    while ((size_t)written_total < obj_len) {
        ssize_t rc = write(fd, obj_buf + written_total, obj_len - (size_t)written_total);
        if (rc < 0) {
            close(fd);
            unlink(tmp_path);
            free(obj_buf);
            return -1;
        }
        written_total += rc;
    }

    if (fsync(fd) < 0) {
        close(fd);
        unlink(tmp_path);
        free(obj_buf);
        return -1;
    }

    if (close(fd) < 0) {
        unlink(tmp_path);
        free(obj_buf);
        return -1;
    }
    fd = -1;

    if (rename(tmp_path, final_path) < 0) {
        unlink(tmp_path);
        free(obj_buf);
        return -1;
    }

    dirfd = open(shard_dir, O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        fsync(dirfd);
        close(dirfd);
    }

    free(obj_buf);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    FILE *f = NULL;
    unsigned char *file_buf = NULL;
    void *data_buf = NULL;
    long file_size;
    char *nul;
    size_t header_len;
    size_t parsed_len;
    ObjectID computed_id;
    int rc = -1;

    object_path(id, path, sizeof(path));
    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) goto cleanup;
    file_size = ftell(f);
    if (file_size < 0) goto cleanup;
    if (fseek(f, 0, SEEK_SET) != 0) goto cleanup;

    file_buf = malloc((size_t)file_size);
    if (file_buf == NULL) goto cleanup;
    if (file_size > 0 && fread(file_buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        goto cleanup;
    }

    compute_hash(file_buf, (size_t)file_size, &computed_id);
    if (memcmp(&computed_id, id, sizeof(ObjectID)) != 0) goto cleanup;

    nul = memchr(file_buf, '\0', (size_t)file_size);
    if (nul == NULL) goto cleanup;
    header_len = (size_t)(nul - (char *)file_buf);

    if (strncmp((char *)file_buf, "blob ", 5) == 0) {
        *type_out = OBJ_BLOB;
        if (sscanf((char *)file_buf + 5, "%zu", &parsed_len) != 1) goto cleanup;
    } else if (strncmp((char *)file_buf, "tree ", 5) == 0) {
        *type_out = OBJ_TREE;
        if (sscanf((char *)file_buf + 5, "%zu", &parsed_len) != 1) goto cleanup;
    } else if (strncmp((char *)file_buf, "commit ", 7) == 0) {
        *type_out = OBJ_COMMIT;
        if (sscanf((char *)file_buf + 7, "%zu", &parsed_len) != 1) goto cleanup;
    } else {
        goto cleanup;
    }

    if (header_len + 1 + parsed_len != (size_t)file_size) goto cleanup;

    data_buf = malloc(parsed_len > 0 ? parsed_len : 1);
    if (data_buf == NULL) goto cleanup;
    if (parsed_len > 0) {
        memcpy(data_buf, nul + 1, parsed_len);
    }

    *data_out = data_buf;
    *len_out = parsed_len;
    rc = 0;

cleanup:
    if (f != NULL) fclose(f);
    free(file_buf);
    if (rc != 0) {
        free(data_buf);
    }
    return rc;
}
