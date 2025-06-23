#ifndef WS_AUDIO_UTILS_H
#define WS_AUDIO_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the audio playback system
 * @return 0 on success, -1 on failure
 */
int ws_audio_init(void);

/**
 * @brief Play received MP3 audio data
 * @param data Pointer to the MP3 audio data
 * @param len Length of the audio data in bytes
 * @return 0 on success, -1 on failure
 */
int ws_audio_play_mp3(const void *data, size_t len);

/**
 * @brief Clean up audio playback resources
 */
void ws_audio_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WS_AUDIO_UTILS_H */
