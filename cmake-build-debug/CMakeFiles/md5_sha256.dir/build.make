# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = "/Users/zaharov/Library/Application Support/JetBrains/Toolbox/apps/CLion/ch-0/193.5662.56/CLion.app/Contents/bin/cmake/mac/bin/cmake"

# The command to remove a file.
RM = "/Users/zaharov/Library/Application Support/JetBrains/Toolbox/apps/CLion/ch-0/193.5662.56/CLion.app/Contents/bin/cmake/mac/bin/cmake" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/zaharov/Documents/YSHA/md5_sha256

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/md5_sha256.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/md5_sha256.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/md5_sha256.dir/flags.make

CMakeFiles/md5_sha256.dir/main.c.o: CMakeFiles/md5_sha256.dir/flags.make
CMakeFiles/md5_sha256.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/md5_sha256.dir/main.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/md5_sha256.dir/main.c.o   -c /Users/zaharov/Documents/YSHA/md5_sha256/main.c

CMakeFiles/md5_sha256.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/md5_sha256.dir/main.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/zaharov/Documents/YSHA/md5_sha256/main.c > CMakeFiles/md5_sha256.dir/main.c.i

CMakeFiles/md5_sha256.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/md5_sha256.dir/main.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/zaharov/Documents/YSHA/md5_sha256/main.c -o CMakeFiles/md5_sha256.dir/main.c.s

# Object files for target md5_sha256
md5_sha256_OBJECTS = \
"CMakeFiles/md5_sha256.dir/main.c.o"

# External object files for target md5_sha256
md5_sha256_EXTERNAL_OBJECTS =

md5_sha256: CMakeFiles/md5_sha256.dir/main.c.o
md5_sha256: CMakeFiles/md5_sha256.dir/build.make
md5_sha256: CMakeFiles/md5_sha256.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable md5_sha256"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/md5_sha256.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/md5_sha256.dir/build: md5_sha256

.PHONY : CMakeFiles/md5_sha256.dir/build

CMakeFiles/md5_sha256.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/md5_sha256.dir/cmake_clean.cmake
.PHONY : CMakeFiles/md5_sha256.dir/clean

CMakeFiles/md5_sha256.dir/depend:
	cd /Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zaharov/Documents/YSHA/md5_sha256 /Users/zaharov/Documents/YSHA/md5_sha256 /Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug /Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug /Users/zaharov/Documents/YSHA/md5_sha256/cmake-build-debug/CMakeFiles/md5_sha256.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/md5_sha256.dir/depend

