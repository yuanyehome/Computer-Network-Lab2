SOURCE  := $(wildcard src/*.cpp)
OBJS    := $(patsubst %.cpp, %.o,$(SOURCE))

TARGET  := test

CC      := g++
LIBS    := -lpcap -lpthread
CXXFLAGS:= -std=c++11
all : $(TARGET)
  
objs : $(OBJS)
  
rebuild: veryclean everything
                
clean:
	rm -f test
	rm -f src/*.o
  
$(TARGET) : $(OBJS)
	$(CC) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)