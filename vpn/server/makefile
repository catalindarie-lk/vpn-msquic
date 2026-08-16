# ==============================================================================
# Compiler & Build Toolchain Configurations
# ==============================================================================
CC       = gcc
CFLAGS   = -std=c23 -Wall -O3 -D_GNU_SOURCE \
			-Wno-stringop-truncation \
			-Wno-unused-includes \
			-Wno-stringop-overflow \
			-Wno-unused-variable \
			-Wno-unused-parameter \
			-Wno-unused-function \
			-Wno-unused-but-set-variable

PROJECT_DIR	:= $(CURDIR)
PARENT_DIR  := $(abspath $(PROJECT_DIR)/..)

INCLUDES = 	-I$(PARENT_DIR)/dep/inc \
			-I$(PARENT_DIR)/common/inc \
			-I$(PROJECT_DIR)/inc \
			-I$(PROJECT_DIR)/inc/engine

DEP_LIB := $(PARENT_DIR)/dep/lib
COMMON_SRC := $(PARENT_DIR)/common/src

# path to look for the library when building the executable
# path to embed in the executable so it knows where to load the shared library from
LDFLAGS  =	-L$(DEP_LIB) \
			-Wl,-rpath,$(DEP_LIB)

LIBS	 =	-lmsquic -lssl -lcrypto -lpthread

TARGET	 =	bin/vpn_server
SRC      =	$(COMMON_SRC)/tun.c \
		   	$(COMMON_SRC)/tun_driver.c \
			$(COMMON_SRC)/net_iface.c \
			$(COMMON_SRC)/pkt_ctrl.c \
			$(COMMON_SRC)/pkt_data.c \
			$(PROJECT_DIR)/src/engine/quic.c \
			$(PROJECT_DIR)/src/engine/stream.c \
			$(PROJECT_DIR)/src/engine/session.c \
			$(PROJECT_DIR)/src/engine/client.c \
			$(PROJECT_DIR)/src/engine/ip_pool.c \
			$(PROJECT_DIR)/src/engine/threads.c \
			$(PROJECT_DIR)/src/engine/vpn_server_engine.c

# ==============================================================================
# Standard Automation Build Recipes
# ==============================================================================
.PHONY: clean server bear

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC) $(LDFLAGS) $(LIBS)
# 	/usr/bin/sudo setcap cap_net_admin,cap_net_bind_service=+ep $(TARGET)

clean:
	rm -f $(TARGET)

# ==============================================================================
# CLI Execution Pipelines
# ==============================================================================
server: $(TARGET)
	/usr/bin/sudo ./$(TARGET)

# Helper recipe to generate clangd language server database
bear: clean
	/usr/bin/sudo bear -- make $(TARGET)
