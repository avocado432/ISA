CC = g++
CFLAGS = -g -Wall -pedantic
FLAGS = -lpcap -lncurses

TARGET = dhcp-stats

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp $(FLAGS)

clean:
	rm $(TARGET)