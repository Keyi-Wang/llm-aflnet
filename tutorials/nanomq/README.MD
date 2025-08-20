## Download and compile nanomq
cd $WORKDIR  
git clone https://github.com/emqx/nanomq.git 
cd nanomq
git submodule update --init --recursive

export CC=afl-clang
export CXX=afl-clang++
export AFL_USE_ASAN=1
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g"
export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g"

mkdir build && cd build
cmake .. 
make

## Fuzzing  
cd $WORKDIR/nanomq
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -d -i $AFLNET/tutorials/nanomq/in-mqtt-v5 -o ./out-nanomq -m none -N tcp://127.0.0.1/1883 -P MQTT -D 10000 -q 3 -s 3 -E -K -R ./build/nanomq/nanomq start

