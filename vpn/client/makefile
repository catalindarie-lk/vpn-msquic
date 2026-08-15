# ==============================================================================
# Compiler & Build Toolchain Configurations
# ==============================================================================
CC =            gcc
CFLAGS =        -Wall -std=c23 -g -o0 -D_GNU_SOURCE \
			-Wno-stringop-truncation \
			-Wno-unused-includes \
			-Wno-stringop-overflow \
			-Wno-unused-variable \
			-Wno-unused-parameter \
			-Wno-unused-function \
			-Wno-unused-but-set-variable

PROJECT_DIR :=  $(CURDIR)
PARENT_DIR :=   $(abspath $(PROJECT_DIR)/..)

# Query GTK+ 3.0 compilation and linking flags dynamically
GTK_CFLAGS  := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS    := $(shell pkg-config --libs gtk+-3.0)

INCLUDES = 	-I$(PARENT_DIR)/dep/inc \
			-I$(PARENT_DIR)/common/inc \
			-I$(PROJECT_DIR)/inc \
			-I$(PROJECT_DIR)/inc/app \
			-I$(PROJECT_DIR)/inc/engine \
			$(GTK_CFLAGS)

DEP_LIB :=      $(PARENT_DIR)/dep/lib
COMMON_DIR :=   $(PARENT_DIR)/common

# path to look for the library when building the executable
# path to embed in the executable so it knows where to load the shared library from
LDFLAGS =       -L$(DEP_LIB) \
                -Wl,-rpath,$(DEP_LIB)

LIBS	 =	-lmsquic -lssl -lcrypto -lpthread $(GTK_LIBS)

TARGET   =      bin/vpn_client
SRC      =      $(COMMON_DIR)/src/tun.c \
                $(COMMON_DIR)/src/tun_driver.c \
                $(COMMON_DIR)/src/net_iface.c \
                $(COMMON_DIR)/src/pkt_ctrl.c \
                $(COMMON_DIR)/src/pkt_data.c \
				$(PROJECT_DIR)/src/engine/domain.c \
                $(PROJECT_DIR)/src/engine/session.c \
                $(PROJECT_DIR)/src/engine/quic.c \
				$(PROJECT_DIR)/src/engine/threads.c \
                $(PROJECT_DIR)/src/engine/vpn_client_engine.c \
				$(PROJECT_DIR)/src/ui/view_logger.c \
				$(PROJECT_DIR)/src/ui/view_controls.c \
				$(PROJECT_DIR)/src/ui/window_main.c \
				$(PROJECT_DIR)/src/app/vpn_app.c \
				$(PROJECT_DIR)/src/app/gtk_app.c \
				$(PROJECT_DIR)/src/vpn_client_gtk.c

# Map .c source files to .o object files in the build step
OBJ      = $(SRC:.c=.o)

# ==============================================================================
# Standard Automation Build Recipes
# ==============================================================================
.PHONY: clean client compile-db

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC) $(LDFLAGS) $(LIBS)

# ==============================================================================
# CLI Execution Pipelines
# ==============================================================================
clean:
	rm -f $(TARGET)


client: $(TARGET)
	/usr/bin/sudo ./$(TARGET)

bear: clean
	/usr/bin/sudo bear -- make $(TARGET)