#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
typedef struct { uint8_t *pointer; size_t length; } NativeBuffer;
extern NativeBuffer sentinel_compile(const uint8_t *, size_t);
extern NativeBuffer sentinel_scan_bytes(int64_t, const uint8_t *, size_t, int32_t);
extern NativeBuffer sentinel_scan_fd(int64_t, int32_t, int64_t, int64_t, int32_t);
extern NativeBuffer sentinel_accept_blob(int64_t, const uint8_t *, size_t);
extern NativeBuffer sentinel_blob(int64_t);
extern NativeBuffer sentinel_cancel(int64_t, int32_t);
extern void sentinel_free(NativeBuffer);
static jbyteArray output(JNIEnv *env, NativeBuffer buffer) {
    if (buffer.pointer == NULL) return NULL;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)buffer.length);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, (jsize)buffer.length, (const jbyte *)buffer.pointer);
    sentinel_free(buffer);
    return result;
}
static jbyteArray array_call(JNIEnv *env, jlong id, jbyteArray array, jboolean complete, int operation) {
    jsize length = array == NULL ? 0 : (*env)->GetArrayLength(env, array);
    size_t limit = operation == 0 ? 262144 : operation == 1 ? 16777216 : 4194304;
    if (array == NULL) {
        jclass type = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (type != NULL) (*env)->ThrowNew(env, type, "null scanner input");
        return NULL;
    }
    uint8_t *data = NULL;
    if ((size_t)length <= limit && length > 0) {
        data = malloc((size_t)length);
        if (data == NULL) {
            jclass type = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
            if (type != NULL) (*env)->ThrowNew(env, type, "scanner input allocation");
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, array, 0, length, (jbyte *)data);
        if ((*env)->ExceptionCheck(env)) { free(data); return NULL; }
    }
    NativeBuffer result = operation == 0 ? sentinel_compile(data, (size_t)length) :
        operation == 1 ? sentinel_scan_bytes(id, data, (size_t)length, complete == JNI_TRUE) : sentinel_accept_blob(id, data, (size_t)length);
    free(data);
    return output(env, result);
}
jbyteArray jni_compile(JNIEnv *env, jbyteArray source) { return array_call(env, 0, source, 0, 0); }
jbyteArray jni_scan_bytes(JNIEnv *env, jlong id, jbyteArray data, jboolean complete) { return array_call(env, id, data, complete, 1); }
jbyteArray jni_scan_fd(JNIEnv *env, jlong id, jint fd, jlong offset, jlong length, jboolean complete) { return output(env, sentinel_scan_fd(id, fd, offset, length, complete == JNI_TRUE)); }
jbyteArray jni_accept_blob(JNIEnv *env, jlong id, jbyteArray blob) { return array_call(env, id, blob, 0, 2); }
jbyteArray jni_blob(JNIEnv *env, jlong id) { return output(env, sentinel_blob(id)); }
jbyteArray jni_cancel(JNIEnv *env, jlong id, jboolean close) { return output(env, sentinel_cancel(id, close == JNI_TRUE)); }

int sentinel_readonly_regular_fd(int fd) {
    if (fd < 0) return 0;
    int owned;
    do { owned = dup(fd); } while (owned < 0 && errno == EINTR);
    if (owned < 0) return 0;
    struct stat metadata;
    int status;
    do { status = fstat(owned, &metadata); } while (status < 0 && errno == EINTR);
    int flags = -1;
    if (status == 0 && S_ISREG(metadata.st_mode)) {
        do { flags = fcntl(owned, F_GETFL); } while (flags < 0 && errno == EINTR);
    }
    int valid = status == 0 && S_ISREG(metadata.st_mode) && flags >= 0 && (flags & O_ACCMODE) == O_RDONLY;
    if (close(owned) != 0) return 0;
    return valid;
}
