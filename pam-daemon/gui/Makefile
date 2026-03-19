CC     = gcc
CFLAGS = $(shell pkg-config --cflags gtk+-3.0) -Wall -Wextra -O2
LIBS   = $(shell pkg-config --libs gtk+-3.0)
TARGET = pam-gui
SRCS   = main.c sys.c gui_gtk.c

HAVE_QR := $(shell pkg-config --exists libqrencode 2>/dev/null && echo yes)
ifeq ($(HAVE_QR),yes)
    CFLAGS += $(shell pkg-config --cflags libqrencode) \
              $(shell pkg-config --cflags cairo) \
              -DHAVE_QRENCODE
    LIBS   += $(shell pkg-config --libs libqrencode) \
              $(shell pkg-config --libs cairo)
    SRCS   += qr.c
endif

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -Dm755 $(TARGET) $(HOME)/.local/bin/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all install clean
