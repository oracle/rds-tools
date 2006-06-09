
all: all-programs

HEADERS = kernel-list.h rdstools.h
COMMON_SOURCES = options.c
SOURCES = $(addsuffix .c,$(PROGRAMS)) $(COMMON_SOURCES)
COMMON_OBJECTS = $(subst .c,.o,$(COMMON_SOURCES))

PROGRAMS = rds-gen rds-sink

all-programs: $(PROGRAMS)

clean:
	rm -f $(PROGRAMS) $(addsuffix .o,$(PROGRAMS)) $(COMMON_OBJECTS)

distclean: clean
	rm -f .*.d


CFLAGS = -O2 -Wall
CPPFLAGS = -DDEBUG_EXE -MD -MP -MF $(@D)/.$(basename $(@F)).d

$(PROGRAMS) : % : %.o $(COMMON_OBJECTS)
	gcc $(CFLAGS) $(LDFLAGS) -o $@ $^

LOCAL_DFILES := $(wildcard .*.d)
ifneq ($(LOCAL_DFILES),)
.PHONY: $(LOCAL_DFILES)
-include $(LOCAL_DFILES)
endif
