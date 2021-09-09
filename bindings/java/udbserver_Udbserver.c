#include "udbserver_Udbserver.h"
#include "udbserver.h"

JNIEXPORT void JNICALL Java_udbserver_Udbserver_udbserver
  (JNIEnv* env, jobject thisObject, long unicorn, int16_t port, int64_t start_addr) {
    udbserver((void *)unicorn, port, start_addr);
}
