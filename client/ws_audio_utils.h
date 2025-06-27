#ifndef WS_AUDIO_UTILS_H
#define WS_AUDIO_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the audio playback system
 * @param buffer_size Size of the circular buffer in bytes (0 for default)
 * @return 0 on success, -1 on failure
 */
int ws_audio_init(size_t buffer_size);

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

/**
 * @brief Stop current audio playback immediately
 * @return 0 on success, -1 on failure
 */
int ws_audio_stop(void);

/**
 * @brief Check if audio is currently playing
 * @return 1 if playing, 0 if not playing
 */
int ws_audio_is_playing(void);

/**
 * @brief Set audio playback interrupt flag
 * This will cause the audio playback to stop at the next opportunity
 */
void ws_audio_interrupt(void);

/**
 * @brief Clear all buffered audio data
 * @return 0 on success, -1 on failure
 */
int ws_audio_clear_buffer(void);

#ifdef __cplusplus
}
#endif

#endif /* WS_AUDIO_UTILS_H */
