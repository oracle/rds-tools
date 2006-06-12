
all: all-programs

CFLAGS = -O2 -Wall
CPPFLAGS = -DDEBUG_EXE -MD -MP -MF $(@D)/.$(basename $(@F)).d

HEADERS = kernel-list.h rdstools.h pfhack.h
COMMON_SOURCES = options.c pfhack.c
SOURCES = $(addsuffix .c,$(PROGRAMS)) $(COMMON_SOURCES)
CLEAN_OBJECTS = $(addsuffix .o,$(PROGRAMS)) $(subst .c,.o,$(COMMON_SOURCES))

ifneq ($(DYNAMIC_PF_RDS),)
CPPFLAGS += -DDYNAMIC_PF_RDS
COMMON_OBJECTS = $(subst .c,.o,$(COMMON_SOURCES))
else
COMMON_OBJECTS = $(subst .c,.o,$(filter-out pfhack.c,$(COMMON_SOURCES)))
endif

PROGRAMS = rds-gen rds-sink

all-programs: $(PROGRAMS)

clean:
	rm -f $(PROGRAMS) $(CLEAN_OBJECTS)

distclean: clean
	rm -f .*.d



$(PROGRAMS) : % : %.o $(COMMON_OBJECTS)
	gcc $(CFLAGS) $(LDFLAGS) -o $@ $^

LOCAL_DFILES := $(wildcard .*.d)
ifneq ($(LOCAL_DFILES),)
.PHONY: $(LOCAL_DFILES)
-include $(LOCAL_DFILES)
endif
