#include "ws_audio_utils.h"
#include "mpg123/mpg123.h"
#include "ao/ao.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Static variables for audio playback
static mpg123_handle *mh = NULL;
static ao_device *dev = NULL;
static int audio_initialized = 0;
static int driver = -1;

int ws_audio_init(void) {
    if (audio_initialized) {
        return 0;  // Already initialized
    }

    // Initialize mpg123
    if (mpg123_init() != MPG123_OK) {
        fprintf(stderr, "[AUDIO] Failed to initialize mpg123\n");
        return -1;
    }

    // Initialize libao
    ao_initialize();
    driver = ao_default_driver_id();
    if (driver < 0) {
        fprintf(stderr, "[AUDIO] Failed to initialize audio output\n");
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

    if (!data || len == 0) {
        fprintf(stderr, "[AUDIO] Invalid audio data\n");
        return -1;
    }

    int err;
    unsigned char *buffer = NULL;
    size_t done;
    int channels, encoding;
    long rate;

    // Create a new mpg123 handle
    mh = mpg123_new(NULL, &err);
    if (!mh) {
        fprintf(stderr, "[AUDIO] Failed to create mpg123 handle: %s\n", 
                mpg123_plain_strerror(err));
        return -1;
    }

    // Configure the handle
    if (mpg123_open_feed(mh) != MPG123_OK) {
        fprintf(stderr, "[AUDIO] Failed to open feed\n");
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }

    // Feed the data
    if (mpg123_feed(mh, data, len) != MPG123_OK) {
        fprintf(stderr, "[AUDIO] Failed to feed audio data\n");
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }

    // Get audio format
    if (mpg123_getformat(mh, &rate, &channels, &encoding) != MPG123_OK) {
        fprintf(stderr, "[AUDIO] Failed to get audio format\n");
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }

    // Set up output format
    ao_sample_format format;
    memset(&format, 0, sizeof(format));
    format.bits = mpg123_encsize(encoding) * 8;
    format.rate = rate;
    format.channels = channels;
    format.byte_format = AO_FMT_NATIVE;
    format.matrix = 0;

    // Open audio device
    dev = ao_open_live(driver, &format, NULL);
    if (!dev) {
        fprintf(stderr, "[AUDIO] Failed to open audio device\n");
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }

    // Allocate buffer for decoding
    buffer = (unsigned char*)malloc(8192);
    if (!buffer) {
        fprintf(stderr, "[AUDIO] Out of memory\n");
        ao_close(dev);
        dev = NULL;
        mpg123_delete(mh);
        mh = NULL;
        return -1;
    }

    // Decode and play
    int first_frame = 1;
    do {
        err = mpg123_read(mh, buffer, 8192, &done);
        if (done > 0) {
            if (first_frame) {
                fprintf(stderr, "[AUDIO] Playing audio: %ldHz, %d channels, %d bits\n", 
                       rate, channels, format.bits);
                first_frame = 0;
            }
            ao_play(dev, (char*)buffer, done);
        }
    } while (err == MPG123_OK && done > 0);

    // Cleanup
    free(buffer);
    ao_close(dev);
    dev = NULL;
    mpg123_delete(mh);
    mh = NULL;

    return 0;
}

void ws_audio_cleanup(void) {
    if (mh) {
        mpg123_delete(mh);
        mh = NULL;
    }
    if (dev) {
        ao_close(dev);
        dev = NULL;
    }
    if (audio_initialized) {
        ao_shutdown();
        mpg123_exit();
        audio_initialized = 0;
    }
    fprintf(stderr, "[AUDIO] Audio system cleaned up\n");
}
