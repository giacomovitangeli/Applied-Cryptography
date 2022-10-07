CC = g++
CXXFLAGS= -g -Wall
LIBS = -lcrypto

OBJ_DIR = ./obj
CLIENT_DIR =  ./client_src
SERVER_DIR = ./server_src
UTIL_DIR = ./util
OUTDIR = .

INCS = $(wildcard *.h $(foreach fd, $(UTIL_DIR), $(fd)/*.h))

SRCS_CL = $(wildcard *.cpp $(foreach fd, $(CLIENT_DIR), $(fd)/*.cpp))
SRCS_SV = $(wildcard *.cpp $(foreach fd, $(SERVER_DIR), $(fd)/*.cpp))
SRCS_UT = $(wildcard *.cpp $(foreach fd, $(UTIL_DIR), $(fd)/*.cpp))

NODIR_SRC_CL = $(notdir $(SRCS_CL))
NODIR_SRC_SV = $(notdir $(SRCS_SV))

OBJS1_CL = $(notdir $(SRCS_CL:cpp=o))
OBJS_CL = $(addprefix $(OBJ_DIR)/, $(OBJS1_CL))

OBJS1_SV = $(notdir $(SRCS_SV:cpp=o))
OBJS_SV = $(addprefix $(OBJ_DIR)/, $(OBJS1_SV))

OBJS1_UT = $(notdir $(SRCS_UT:cpp=o))
OBJS_UT = $(addprefix $(OBJ_DIR)/, $(OBJS1_UT))

INC_DIRS = -I./ $(addprefix -I, $(SUBDIR))

all: client server

client: $(OBJS_CL) $(OBJS_UT)
	  $(CC) $(OBJS_CL) $(OBJS_UT) -o $@ $(LIBS)
server: $(OBJS_SV) $(OBJS_UT)
	$(CC) $(OBJS_SV) $(OBJS_UT) -o $@ $(LIBS)

$(OBJ_DIR)/main_client.o: $(CLIENT_DIR)/main_client.cpp $(INCS)
	$(CC) $(CXXFLAGS) -c $< -o $@ 

$(OBJ_DIR)/main_server.o: $(SERVER_DIR)/main_server.cpp $(INCS)
	$(CC) $(CXXFLAGS) -c $< -o $@ 

$(OBJ_DIR)/util_fun.o: $(UTIL_DIR)/util_fun.cpp $(UTIL_DIR)/data_struct.h $(INCS)
	$(CC) $(CXXFLAGS) -c $< -o $@ 

clean:
	rm ./obj/*.o client server
	clear
