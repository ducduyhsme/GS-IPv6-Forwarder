# Makefile for GSv6Fwd on Linux/Ubuntu
#
# Requirements:
#   sudo apt-get install build-essential libminiupnpc-dev
#

CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++11
LDFLAGS = -lpthread -lminiupnpc

# Source files
SRCDIR = GSv6Fwd
SOURCES = $(SRCDIR)/GSv6Fwd.cpp $(SRCDIR)/pcp.cpp
OBJECTS = $(SOURCES:.cpp=.o)

# Output binary
TARGET = gsv6fwd

# Include directories
INCLUDES = -I$(SRCDIR) -Ilibs/include

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	install -D -m 755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed $(TARGET) to /usr/local/bin/"
	@echo ""
	@echo "To run as a daemon, you can use:"
	@echo "  sudo $(TARGET) -d"
	@echo ""
	@echo "Or create a systemd service (see README.md for instructions)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled $(TARGET) from /usr/local/bin/"

# Create a systemd service file
systemd-service:
	@echo "[Unit]" > gsv6fwd.service
	@echo "Description=GameStream IPv6 Forwarder" >> gsv6fwd.service
	@echo "After=network.target" >> gsv6fwd.service
	@echo "" >> gsv6fwd.service
	@echo "[Service]" >> gsv6fwd.service
	@echo "Type=simple" >> gsv6fwd.service
	@echo "ExecStart=/usr/local/bin/gsv6fwd" >> gsv6fwd.service
	@echo "Restart=always" >> gsv6fwd.service
	@echo "RestartSec=5" >> gsv6fwd.service
	@echo "" >> gsv6fwd.service
	@echo "[Install]" >> gsv6fwd.service
	@echo "WantedBy=multi-user.target" >> gsv6fwd.service
	@echo "Created gsv6fwd.service"
	@echo ""
	@echo "To install the service:"
	@echo "  sudo cp gsv6fwd.service /etc/systemd/system/"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable gsv6fwd"
	@echo "  sudo systemctl start gsv6fwd"
