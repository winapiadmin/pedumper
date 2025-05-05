# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -g

# Source files
SRCS = main.cpp disasm_analyzer.cpp
# Executable name
TARGET = pedumper

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    CXXFLAGS += -I/usr/include/capstone
    LDFLAGS = -lcapstone
    SRCS += altimpl.cpp utils.cpp
    TARGET = pedumper-linux
else ifeq ($(UNAME_S),Darwin)
    CXXFLAGS += -I/usr/local/include
    LDFLAGS = -L/usr/local/lib -lcapstone
    SRCS += altimpl.cpp utils.cpp
    TARGET = pedumper-linux
else ifeq ($(UNAME_S),Windows)
    CXXFLAGS += -I/path/to/capstone/include
    LDFLAGS = -L/path/to/capstone/lib -lcapstone
endif

# Object files
OBJS = $(SRCS:.cpp=.o)

# Build target
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS) $(EXTRACXXFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

cleanall: clean
