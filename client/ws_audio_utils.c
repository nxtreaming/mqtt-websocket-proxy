#include "ws_audio_utils.h"
#include "mpg123/mpg123.h"
#include "ao/ao.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif

// Configuration constants
#define AUDIO_BUFFER_SIZE (32768)  // 32KB buffer for better performance
#define MP3_BUFFER_SIZE (65536)   // 64KB circular buffer for MP3 data
#define DEBUG_AUDIO 0              // Set to 0 to disable detailed audio debugging

// Static variables for audio playback
static mpg123_handle *mh = NULL;
static ao_device *dev = NULL;
static int audio_initialized = 0;
static int driver = -1;

// Audio format tracking
static long current_rate = 0;
static int current_channels = 0;
static int current_encoding = 0;
static unsigned char *decode_buffer = NULL;

// Circular buffer structure for MP3 data
typedef struct {
    unsigned char *buffer;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t size;
    int initialized;
} circular_buffer_t;

static circular_buffer_t mp3_buffer = {NULL, 0, 0, 0, 0, 0};



// Debug macro for audio-related messages
#define AUDIO_DEBUG(fmt, ...) \
    do { \
        if (DEBUG_AUDIO) { \
            fprintf(stderr, "[AUDIO_DEBUG] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @brief Initialize the persistent mpg123 handle
 * @return 0 on success, -1 on failure
 */
static int initialize_mpg123_handle(void) {
    int err;
    
    // Clean up existing handle if any
    if (mh) {
        mpg123_delete(mh);
        mh = NULL;
    }
    
    // Create a new mpg123 handle with optimized parameters
    mh = mpg123_new(NULL, &err);
    if (!mh) {
        fprintf(stderr, "[AUDIO] Failed to create mpg123 handle: %s\n", 
                mpg123_plain_strerror(err));
        return -1;
    }
    
    // Set higher quality decoding for better audio
    mpg123_param(mh, MPG123_RESYNC_LIMIT, -1, 0.0); // No resync limit for better error recovery
    mpg123_param(mh, MPG123_ADD_FLAGS, MPG123_FORCE_FLOAT, 0.0); // Force float decoding for better quality
    mpg123_param(mh, MPG123_VERBOSE, 0, 0.0); // Disable verbose output
    mpg123_param(mh, MPG123_FLAGS, MPG123_QUIET, 0.0); // Set quiet mode
    
    // Completely disable debug output
    mpg123_param(mh, MPG123_ADD_FLAGS, MPG123_QUIET, 0.0);
    
    // Configure the handle for feed mode
    if (mpg123_open_feed(mh) != MPG123_OK) {
        fprintf(stderr, "[AUDIO] Failed to open feed\n");
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }
    
    return 0;
}

/**
 * @brief Initialize or reinitialize the audio output device
 * @param rate Sample rate in Hz
 * @param channels Number of audio channels
 * @param encoding MPG123 encoding format
 * @return 0 on success, -1 on failure
 */
static int initialize_audio_device(long rate, int channels, int encoding) {
    // Check if we need to reinitialize (format changed)
    if (dev && rate == current_rate && channels == current_channels && encoding == current_encoding) {
        AUDIO_DEBUG("Reusing existing audio device with same format");
        return 0; // No need to reinitialize
    }
    
    // Close existing device if any
    if (dev) {
        AUDIO_DEBUG("Closing existing audio device due to format change");
        ao_close(dev);
        dev = NULL;
    }
    
    // Set up output format
    ao_sample_format format;
    memset(&format, 0, sizeof(format));
    format.bits = mpg123_encsize(encoding) * 8;
    format.rate = rate;
    format.channels = channels;
    format.byte_format = AO_FMT_NATIVE;
    format.matrix = 0;
    
    // Open audio device with appropriate options
    ao_option *options = NULL;
    #ifdef _WIN32
    // Try to use DirectSound driver if available
    int ds_driver = ao_driver_id("directsound");
    if (ds_driver >= 0) {
        driver = ds_driver;
        fprintf(stderr, "[AUDIO] Using DirectSound driver\n");
    } else {
        fprintf(stderr, "[AUDIO] DirectSound not available, using default driver\n");
    }
    #endif
    
    AUDIO_DEBUG("Opening audio device: %ldHz, %d channels, %d bits", rate, channels, format.bits);
    
    // Try with the selected driver first
    dev = ao_open_live(driver, &format, options);
    
    // If that fails, try the default driver
    if (!dev && driver != ao_default_driver_id()) {
        fprintf(stderr, "[AUDIO] Failed with selected driver, trying default driver\n");
        driver = ao_default_driver_id();
        dev = ao_open_live(driver, &format, options);
    }
    
    // If still fails, try with NULL options
    if (!dev) {
        fprintf(stderr, "[AUDIO] Failed with options, trying without options\n");
        dev = ao_open_live(driver, &format, NULL);
    }
    
    // If all attempts failed
    if (!dev) {
        fprintf(stderr, "[AUDIO] Failed to open any audio device\n");
        if (options) {
            ao_free_options(options);
        }
        return -1;
    }
    
    // Free options now that we're done with them
    if (options) {
        ao_free_options(options);
    }
    
    // Store current format for future reference
    current_rate = rate;
    current_channels = channels;
    current_encoding = encoding;
    
    fprintf(stderr, "[AUDIO] Audio device initialized: %ldHz, %d channels, %d bits\n", 
            rate, channels, format.bits);
    return 0;
}

// Flag to track if stderr has been redirected
static int stderr_redirected = 0;

// Function to disable mpg123 debug output by redirecting stderr
static void disable_mpg123_debug(void) {
    if (!stderr_redirected) {
#ifdef _WIN32
        // On Windows, redirect stderr to NUL device
        if (freopen("NUL", "w", stderr) != NULL) {
            stderr_redirected = 1;
        }
#else
        // On Unix-like systems, redirect stderr to /dev/null
        if (freopen("/dev/null", "w", stderr) != NULL) {
            stderr_redirected = 1;
        }
#endif
    }
}

// Function to restore original stderr
static void restore_stderr(void) {
    if (stderr_redirected) {
        // We can't easily restore the original stderr in standard C
        // Instead, we'll just reopen it to the console
#ifdef _WIN32
        freopen("CON", "w", stderr);
#else
        freopen("/dev/tty", "w", stderr);
#endif
        stderr_redirected = 0;
    }
}

/**
 * @brief Write data to the circular buffer
 * @param data Pointer to the data to write
 * @param len Length of the data in bytes
 * @return Number of bytes written
 */
static size_t circular_buffer_write(circular_buffer_t *cb, const unsigned char *data, size_t len) {
    if (!cb || !cb->buffer || !cb->initialized || !data || len == 0) {
        return 0;
    }
    
    // Calculate available space
    size_t available = cb->capacity - cb->size;
    if (available == 0) {
        AUDIO_DEBUG("Circular buffer full, cannot write more data");
        return 0;
    }
    
    // Limit write size to available space
    size_t write_size = (len > available) ? available : len;
    
    // Write data in two parts if necessary (wrap around buffer end)
    size_t first_chunk = cb->capacity - cb->tail;
    if (write_size <= first_chunk) {
        // Simple case: no wrap around
        memcpy(cb->buffer + cb->tail, data, write_size);
    } else {
        // Complex case: wrap around
        memcpy(cb->buffer + cb->tail, data, first_chunk);
        memcpy(cb->buffer, data + first_chunk, write_size - first_chunk);
    }
    
    // Update tail position
    cb->tail = (cb->tail + write_size) % cb->capacity;
    cb->size += write_size;
    
    AUDIO_DEBUG("Wrote %zu bytes to circular buffer (size now: %zu/%zu)", 
               write_size, cb->size, cb->capacity);
    
    return write_size;
}

/**
 * @brief Read data from the circular buffer
 * @param dest Destination buffer
 * @param len Maximum number of bytes to read
 * @return Number of bytes read
 */
static size_t circular_buffer_read(circular_buffer_t *cb, unsigned char *dest, size_t len) {
    if (!cb || !cb->buffer || !cb->initialized || !dest || len == 0 || cb->size == 0) {
        return 0;
    }
    
    // Limit read size to available data
    size_t read_size = (len > cb->size) ? cb->size : len;
    
    // Read data in two parts if necessary (wrap around buffer end)
    size_t first_chunk = cb->capacity - cb->head;
    if (read_size <= first_chunk) {
        // Simple case: no wrap around
        memcpy(dest, cb->buffer + cb->head, read_size);
    } else {
        // Complex case: wrap around
        memcpy(dest, cb->buffer + cb->head, first_chunk);
        memcpy(dest + first_chunk, cb->buffer, read_size - first_chunk);
    }
    
    // Update head position
    cb->head = (cb->head + read_size) % cb->capacity;
    cb->size -= read_size;
    
    AUDIO_DEBUG("Read %zu bytes from circular buffer (size now: %zu/%zu)", 
              read_size, cb->size, cb->capacity);
    
    return read_size;
}

/**
 * @brief Peek at data in the circular buffer without removing it
 * @param dest Destination buffer
 * @param len Maximum number of bytes to peek
 * @return Number of bytes peeked
 */
static size_t circular_buffer_peek(circular_buffer_t *cb, unsigned char *dest, size_t len) {
    if (!cb || !cb->buffer || !cb->initialized || !dest || len == 0 || cb->size == 0) {
        return 0;
    }
    
    // Limit peek size to available data
    size_t peek_size = (len > cb->size) ? cb->size : len;
    
    // Peek data in two parts if necessary (wrap around buffer end)
    size_t first_chunk = cb->capacity - cb->head;
    if (peek_size <= first_chunk) {
        // Simple case: no wrap around
        memcpy(dest, cb->buffer + cb->head, peek_size);
    } else {
        // Complex case: wrap around
        memcpy(dest, cb->buffer + cb->head, first_chunk);
        memcpy(dest + first_chunk, cb->buffer, peek_size - first_chunk);
    }
    
    return peek_size;
}

int ws_audio_init(void) {
    if (audio_initialized) {
        fprintf(stderr, "[AUDIO] Audio system already initialized\n");
        return 0;  // Already initialized
    }

    fprintf(stderr, "[AUDIO] Initializing audio system...\n");
    
    // Redirect stderr to null device to suppress mpg123 debug output
    disable_mpg123_debug();
    
    // Initialize mpg123 with debug output disabled
    int mpg_err = mpg123_init();
    if (mpg_err != MPG123_OK) {
        // Temporarily restore stderr for our own error message
        restore_stderr();
        fprintf(stderr, "[AUDIO] Failed to initialize mpg123: %s\n", mpg123_plain_strerror(mpg_err));
        return -1;
    }
    
    // Disable all debug output at the global level
    mpg123_param(NULL, MPG123_FLAGS, MPG123_QUIET, 0.0);
    mpg123_param(NULL, MPG123_VERBOSE, 0, 0.0);

    // Initialize libao
    ao_initialize();
    
    // Try to get DirectSound driver on Windows
    #ifdef _WIN32
    driver = ao_driver_id("directsound");
    if (driver >= 0) {
        fprintf(stderr, "[AUDIO] Using DirectSound driver\n");
    } else {
        fprintf(stderr, "[AUDIO] DirectSound not available, using default driver\n");
        driver = ao_default_driver_id();
    }
    #else
    driver = ao_default_driver_id();
    #endif
    
    if (driver < 0) {
        fprintf(stderr, "[AUDIO] Failed to initialize audio output\n");
        mpg123_exit();
        return -1;
    }
    
    // List available drivers for debugging
    fprintf(stderr, "[AUDIO] Available drivers:\n");
    int driver_count;
    ao_info** driver_info = ao_driver_info_list(&driver_count);
    if (driver_info) {
        for (int i = 0; i < driver_count; i++) {
            fprintf(stderr, "  - %s: %s\n", driver_info[i]->short_name, driver_info[i]->name);
        }
    }
    
    // Allocate persistent decode buffer
    decode_buffer = (unsigned char*)malloc(AUDIO_BUFFER_SIZE);
    if (!decode_buffer) {
        fprintf(stderr, "[AUDIO] Failed to allocate decode buffer\n");
        ao_shutdown();
        mpg123_exit();
        return -1;
    }
    
    // Allocate circular buffer for MP3 data
    mp3_buffer.buffer = (unsigned char*)malloc(MP3_BUFFER_SIZE);
    if (!mp3_buffer.buffer) {
        fprintf(stderr, "[AUDIO] Failed to allocate MP3 circular buffer\n");
        free(decode_buffer);
        decode_buffer = NULL;
        ao_shutdown();
        mpg123_exit();
        return -1;
    }
    mp3_buffer.capacity = MP3_BUFFER_SIZE;
    mp3_buffer.head = 0;
    mp3_buffer.tail = 0;
    mp3_buffer.size = 0;
    mp3_buffer.initialized = 1;
    
    fprintf(stderr, "[AUDIO] MP3 circular buffer initialized with %zu bytes capacity\n", mp3_buffer.capacity);
    
    // Initialize mpg123 handle
    if (initialize_mpg123_handle() != 0) {
        free(decode_buffer);
        decode_buffer = NULL;
        ao_shutdown();
        mpg123_exit();
        return -1;
    }

    audio_initialized = 1;
    fprintf(stderr, "[AUDIO] Audio system initialized successfully\n");
    return 0;
}

int ws_audio_play_mp3(const void *data, size_t len) {
    if (!audio_initialized) {
        fprintf(stderr, "[AUDIO] Audio system not initialized\n");
        return -1;
    }
    
    // Make sure debug output is disabled during playback
    disable_mpg123_debug();

    if (!data || len == 0) {
        fprintf(stderr, "[AUDIO] Invalid audio data\n");
        return -1;
    }
    
    fprintf(stderr, "[AUDIO] Processing MP3 data (%zu bytes)\n", len);
    
    // Ensure mpg123 handle is valid
    if (!mh && initialize_mpg123_handle() != 0) {
        fprintf(stderr, "[AUDIO] Failed to initialize mpg123 handle\n");
        return -1;
    }
    
    // Add new data to circular buffer
    size_t bytes_written = circular_buffer_write(&mp3_buffer, data, len);
    if (bytes_written < len) {
        fprintf(stderr, "[AUDIO] Warning: Could only buffer %zu of %zu bytes (buffer full)\n", 
                bytes_written, len);
    }
    
    // Use a temporary buffer for feeding data to mpg123
    unsigned char temp_buffer[4096];
    size_t bytes_read = circular_buffer_read(&mp3_buffer, temp_buffer, sizeof(temp_buffer));
    
    // Feed the data from circular buffer
    if (bytes_read > 0) {
        int feed_result = mpg123_feed(mh, temp_buffer, bytes_read);
        if (feed_result != MPG123_OK) {
            fprintf(stderr, "[AUDIO] Failed to feed audio data: %s\n", mpg123_plain_strerror(feed_result));
            // Try to recover by reinitializing the handle
            if (initialize_mpg123_handle() != 0) {
                return -1;
            }
            // Try feeding again
            feed_result = mpg123_feed(mh, temp_buffer, bytes_read);
            if (feed_result != MPG123_OK) {
                fprintf(stderr, "[AUDIO] Failed to feed audio data after reinit: %s\n", mpg123_plain_strerror(feed_result));
                return -1;
            }
        }
    }

    int err;
    size_t done;
    int channels = 0, encoding = 0;
    long rate = 0;
    int format_initialized = 0;
    int bytes_decoded = 0;
    int max_decode_iterations = 10; // Limit iterations to prevent blocking too long

    // Decode and play loop
    int iterations = 0;
    do {
        // Read decoded data
        err = mpg123_read(mh, decode_buffer, AUDIO_BUFFER_SIZE, &done);
        
        AUDIO_DEBUG("mpg123_read returned %d, decoded %zu bytes", err, done);
        
        // Handle format detection or changes
        if (err == MPG123_NEW_FORMAT) {
            // Get the new audio format
            if (mpg123_getformat(mh, &rate, &channels, &encoding) != MPG123_OK) {
                fprintf(stderr, "[AUDIO] Failed to get audio format\n");
                continue; // Try to continue anyway
            }
            
            fprintf(stderr, "[AUDIO] New audio format detected: %ldHz, %d channels, encoding %d\n", 
                   rate, channels, encoding);
            
            // Initialize or update audio device with detected format
            if (initialize_audio_device(rate, channels, encoding) != 0) {
                fprintf(stderr, "[AUDIO] Failed to initialize audio device for new format\n");
                continue; // Try to continue anyway
            }
            
            format_initialized = 1;
        }
        
        // If we haven't initialized the format yet but have data, try to get format
        if (!format_initialized && done > 0) {
            if (mpg123_getformat(mh, &rate, &channels, &encoding) == MPG123_OK) {
                fprintf(stderr, "[AUDIO] Audio format detected: %ldHz, %d channels, encoding %d\n", 
                       rate, channels, encoding);
                
                if (initialize_audio_device(rate, channels, encoding) == 0) {
                    format_initialized = 1;
                }
            }
        }
        
        // Play decoded data if we have a valid device and data
        if (dev && done > 0 && format_initialized) {
            AUDIO_DEBUG("Playing %zu bytes of audio", done);
            ao_play(dev, (char*)decode_buffer, done);
            bytes_decoded += done;
        }
        
        // If we need more data and have some in the buffer, feed it
        if (err == MPG123_NEED_MORE && mp3_buffer.size > 0) {
            unsigned char additional_buffer[4096];
            size_t additional_bytes_read = circular_buffer_read(&mp3_buffer, additional_buffer, sizeof(additional_buffer));
            
            if (additional_bytes_read > 0) {
                AUDIO_DEBUG("Feeding %zu more bytes from circular buffer", additional_bytes_read);
                int feed_result = mpg123_feed(mh, additional_buffer, additional_bytes_read);
                if (feed_result == MPG123_OK) {
                    // Reset error to continue the loop
                    err = MPG123_OK;
                }
            }
        }
        
        // Prevent infinite loop by limiting iterations
        iterations++;
        if (iterations >= max_decode_iterations) {
            AUDIO_DEBUG("Reached maximum decode iterations (%d)", max_decode_iterations);
            break;
        }
        
    } while (err == MPG123_OK || err == MPG123_NEW_FORMAT);
    
    // Check for expected end conditions
    if (err == MPG123_DONE) {
        fprintf(stderr, "[AUDIO] Decoding completed successfully (%d bytes)\n", bytes_decoded);
        return 0;
    } else if (err == MPG123_NEED_MORE) {
        // This is normal - we'll get more data in the next callback
        AUDIO_DEBUG("Decoder needs more data (%d bytes decoded so far)", bytes_decoded);
        return 0;
    } else if (err != MPG123_OK && bytes_decoded == 0) {
        fprintf(stderr, "[AUDIO] Decoding error: %s (no bytes decoded)\n", 
                mpg123_plain_strerror(err));
        return -1;
    }
    
    return 0; // Return success if we got here
}

void ws_audio_cleanup(void) {
    fprintf(stderr, "[AUDIO] Cleaning up audio system...\n");
    
    // First flush any pending audio with silence
    if (dev && audio_initialized) {
        unsigned char silence[4096] = {0};
        ao_play(dev, (char*)silence, sizeof(silence));
        fprintf(stderr, "[AUDIO] Flushed audio device with silence\n");
    }
    
    // Clean up mpg123 handle
    if (mh) {
        fprintf(stderr, "[AUDIO] Cleaning up mpg123 handle\n");
        mpg123_delete(mh);
        mh = NULL;
    }
    
    // Close audio device
    if (dev) {
        fprintf(stderr, "[AUDIO] Closing audio device\n");
        ao_close(dev);
        dev = NULL;
    }
    
    // Free decode buffer
    if (decode_buffer) {
        free(decode_buffer);
        decode_buffer = NULL;
    }
    
    // Free circular buffer
    if (mp3_buffer.buffer) {
        fprintf(stderr, "[AUDIO] Freeing MP3 circular buffer\n");
        free(mp3_buffer.buffer);
        mp3_buffer.buffer = NULL;
        mp3_buffer.initialized = 0;
    }
    
    // Shut down audio libraries
    if (audio_initialized) {
        fprintf(stderr, "[AUDIO] Shutting down audio libraries\n");
        ao_shutdown();
        mpg123_exit();
        audio_initialized = 0;
        
        // Reset format tracking
        current_rate = 0;
        current_channels = 0;
        current_encoding = 0;
    }
    
    fprintf(stderr, "[AUDIO] Audio system cleaned up successfully\n");
    
    // Restore original stderr
    restore_stderr();
}
