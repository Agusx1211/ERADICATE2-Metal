#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <random>
#include <set>

#include "hexadecimal.hpp"
#include "ArgParser.hpp"
#include "ModeFactory.hpp"
#include "types.hpp"
#include "help.hpp"
#include "sha3.hpp"
#include "Speed.hpp"

#define ERADICATE2_SPEEDSAMPLES 20
#define ERADICATE2_MAX_SCORE 40

// Optional base salt (32 bytes) supplied via CLI; empty means random fallback.
static std::string g_baseSaltBinary;

static std::string readTextFile(const char * path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) return {};
    std::ostringstream contents;
    contents << in.rdbuf();
    return contents.str();
}

static void trim(std::string & s) {
    const auto iLeft = s.find_first_not_of(" \t\r\n");
    if (iLeft != std::string::npos) s.erase(0, iLeft);
    const auto iRight = s.find_last_not_of(" \t\r\n");
    if (iRight != std::string::npos) {
        const auto count = s.length() - iRight - 1;
        s.erase(iRight + 1, count);
    }
}

static std::vector<uint64_t> makeInitialStateQ(const std::string &addressBinary, const std::string &initCodeDigest) {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<unsigned int> distr;

    ethhash h = { 0 };
    h.b[0] = 0xff;
    for (int i = 0; i < 20 && i < (int)addressBinary.size(); ++i) h.b[i + 1] = (uint8_t)addressBinary[i];
    for (int i = 0; i < 32; ++i) h.b[i + 21] = (uint8_t)distr(eng);
    // If a base salt is provided via CLI, override the random salt
    if (!g_baseSaltBinary.empty()) {
        for (int i = 0; i < 32 && i < (int)g_baseSaltBinary.size(); ++i) h.b[i + 21] = (uint8_t)g_baseSaltBinary[i];
    }
    for (int i = 0; i < 32 && i < (int)initCodeDigest.size(); ++i) h.b[i + 53] = (uint8_t)initCodeDigest[i];
    h.b[85] ^= 0x01;
    std::vector<uint64_t> q(25);
    for (int i = 0; i < 25; ++i) q[i] = h.q[i];
    return q;
}

static std::string keccakDigest32(const std::string &data) {
    char digest[32];
    sha3(data.c_str(), data.size(), digest, 32);
    return std::string(digest, 32);
}

static void printFound(const result &r, uint8_t score, const std::chrono::time_point<std::chrono::steady_clock> &timeStart) {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - timeStart).count();
    const std::string strSalt = toHex(r.salt, 32);
    const std::string strPublic = toHex(r.hash, 20);
    const std::string clr = "\33[2K\r";
    std::cout << clr << "  Time: " << std::setw(5) << seconds << "s Score: " << std::setw(2) << (int)score
              << " Salt: 0x" << strSalt << " Address: 0x" << strPublic << std::endl;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        try {
            ArgParser argp(argc, argv);
            bool bHelp = false;
            bool bModeBenchmark = false;
            bool bModeZeroBytes = false;
            bool bModeZeros = false;
            bool bModeLetters = false;
            bool bModeNumbers = false;
            std::string strModeLeading;
            std::string strModeMatching;
            bool bModeLeadingRange = false;
            bool bModeRange = false;
            bool bModeMirror = false;
            bool bModeDoubles = false;
            int rangeMin = 0;
            int rangeMax = 0;
            std::vector<size_t> vDeviceSkipIndex;
            size_t worksizeLocal = 128;
            size_t worksizeMax = 0; // unused in Metal path, dispatch 1 pass
            size_t size = 16777216;
            std::string strAddress;
            std::string strInitCode;
            std::string strInitCodeFile;
            std::string strBaseHash; // optional 32-byte base salt/hash in hex

            argp.addSwitch('h', "help", bHelp);
            argp.addSwitch('0', "benchmark", bModeBenchmark);
            argp.addSwitch('z', "zero-bytes", bModeZeroBytes);
            argp.addSwitch('1', "zeros", bModeZeros);
            argp.addSwitch('2', "letters", bModeLetters);
            argp.addSwitch('3', "numbers", bModeNumbers);
            argp.addSwitch('4', "leading", strModeLeading);
            argp.addSwitch('5', "matching", strModeMatching);
            argp.addSwitch('6', "leading-range", bModeLeadingRange);
            argp.addSwitch('7', "range", bModeRange);
            argp.addSwitch('8', "mirror", bModeMirror);
            argp.addSwitch('9', "leading-doubles", bModeDoubles);
            argp.addSwitch('m', "min", rangeMin);
            argp.addSwitch('M', "max", rangeMax);
            argp.addMultiSwitch('s', "skip", vDeviceSkipIndex);
            argp.addSwitch('w', "work", worksizeLocal);
            argp.addSwitch('W', "work-max", worksizeMax);
            argp.addSwitch('S', "size", size);
            argp.addSwitch('A', "address", strAddress);
            argp.addSwitch('I', "init-code", strInitCode);
            argp.addSwitch('i', "init-code-file", strInitCodeFile);
            argp.addSwitch('H', "base-hash", strBaseHash);

            if (!argp.parse()) {
                std::cout << "error: bad arguments, try again :<" << std::endl;
                return 1;
            }
            if (bHelp) { std::cout << g_strHelp << std::endl; return 0; }

            if (!strInitCodeFile.empty()) {
                std::ifstream ifs(strInitCodeFile);
                if (!ifs.is_open()) { std::cout << "error: failed to open input file for init code" << std::endl; return 1; }
                strInitCode.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
            }

            trim(strInitCode);
            const std::string strAddressBinary = parseHexadecimalBytes(strAddress);
            const std::string strInitCodeBinary = parseHexadecimalBytes(strInitCode);
            const std::string strInitCodeDigest = keccakDigest32(strInitCodeBinary);
            // Optional base-hash parsing and validation
            if (!strBaseHash.empty()) {
                g_baseSaltBinary = parseHexadecimalBytes(strBaseHash);
                if (g_baseSaltBinary.size() != 32) {
                    std::cout << "error: --base-hash must be exactly 32 bytes (64 hex chars)" << std::endl;
                    return 1;
                }
            } else {
                g_baseSaltBinary.clear();
            }
            const auto initQ = makeInitialStateQ(strAddressBinary, strInitCodeDigest);

            mode modeSel = ModeFactory::benchmark();
            if (bModeBenchmark) modeSel = ModeFactory::benchmark();
            else if (bModeZeroBytes) modeSel = ModeFactory::zerobytes();
            else if (bModeZeros) modeSel = ModeFactory::zeros();
            else if (bModeLetters) modeSel = ModeFactory::letters();
            else if (bModeNumbers) modeSel = ModeFactory::numbers();
            else if (!strModeLeading.empty()) modeSel = ModeFactory::leading(strModeLeading.front());
            else if (!strModeMatching.empty()) modeSel = ModeFactory::matching(strModeMatching);
            else if (bModeLeadingRange) modeSel = ModeFactory::leadingRange(rangeMin, rangeMax);
            else if (bModeRange) modeSel = ModeFactory::range(rangeMin, rangeMax);
            else if (bModeMirror) modeSel = ModeFactory::mirror();
            else if (bModeDoubles) modeSel = ModeFactory::doubles();
            else { std::cout << g_strHelp << std::endl; return 0; }

            NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();
            std::vector<id<MTLDevice>> selectedDevices;
            std::cout << "Devices:" << std::endl;
            for (NSUInteger i = 0; i < devices.count; ++i) {
                if (std::find(vDeviceSkipIndex.begin(), vDeviceSkipIndex.end(), (size_t)i) != vDeviceSkipIndex.end()) continue;
                id<MTLDevice> dev = devices[i];
                std::cout << "  GPU" << i << ": " << [[dev name] UTF8String] << std::endl;
                selectedDevices.push_back(dev);
            }
            if (selectedDevices.empty()) return 1;

            const std::string metalSrc = readTextFile("eradicate2.metal");
            if (metalSrc.empty()) { std::cerr << "error: failed to read eradicate2.metal" << std::endl; return 1; }

            struct DeviceState {
                id<MTLDevice> dev;
                id<MTLCommandQueue> queue;
                id<MTLComputePipelineState> pso;
                id<MTLBuffer> resultBuf; // ERADICATE2_MAX_SCORE + 1 results
                id<MTLBuffer> modeBuf;
                id<MTLBuffer> initQBuf;  // 25 * uint64
                uint8_t scoreMax;
                uint32_t index;
                uint32_t round;
            };

            std::vector<DeviceState> states;
            for (size_t i = 0; i < selectedDevices.size(); ++i) {
                id<MTLDevice> dev = selectedDevices[i];
                NSError *err = nil;
                MTLCompileOptions *opts = [[MTLCompileOptions alloc] init];
                id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:metalSrc.c_str()] options:opts error:&err];
                if (!lib) { std::cerr << "error: Metal compile failed: " << [[err localizedDescription] UTF8String] << std::endl; return 1; }
                id<MTLFunction> fn = [lib newFunctionWithName:@"eradicate2_iterate"];
                id<MTLComputePipelineState> pso = [dev newComputePipelineStateWithFunction:fn error:&err];
                if (!pso) { std::cerr << "error: pipeline state init failed: " << [[err localizedDescription] UTF8String] << std::endl; return 1; }
                id<MTLCommandQueue> queue = [dev newCommandQueue];

                const NSUInteger resCount = ERADICATE2_MAX_SCORE + 1;
                id<MTLBuffer> resultBuf = [dev newBufferWithLength:resCount * sizeof(result) options:MTLResourceStorageModeShared];
                // zero initialize
                memset([resultBuf contents], 0, resCount * sizeof(result));
                id<MTLBuffer> modeBuf = [dev newBufferWithLength:sizeof(mode) options:MTLResourceStorageModeShared];
                memcpy([modeBuf contents], &modeSel, sizeof(mode));
                id<MTLBuffer> initQBuf = [dev newBufferWithLength:25 * sizeof(uint64_t) options:MTLResourceStorageModeShared];
                memcpy([initQBuf contents], initQ.data(), 25 * sizeof(uint64_t));

                DeviceState s{dev, queue, pso, resultBuf, modeBuf, initQBuf, 0, (uint32_t)i, 0};
                states.push_back(s);
            }

            std::cout << std::endl << "Running..." << std::endl << std::endl;

            auto timeStart = std::chrono::steady_clock::now();
            Speed speed;

            bool quit = false;
            uint8_t globalBest = 0;
            const NSUInteger threadsRequested = worksizeLocal ? worksizeLocal : 0;

            while (!quit) {
                for (auto &st : states) {
                    st.round += 1;
                    id<MTLCommandBuffer> cb = [st.queue commandBuffer];
                    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
                    [enc setComputePipelineState:st.pso];
                    [enc setBuffer:st.resultBuf offset:0 atIndex:0];
                    [enc setBuffer:st.modeBuf offset:0 atIndex:1];
                    [enc setBytes:&st.scoreMax length:sizeof(uint8_t) atIndex:2];
                    [enc setBytes:&st.index length:sizeof(uint32_t) atIndex:3];
                    [enc setBytes:&st.round length:sizeof(uint32_t) atIndex:4];
                    [enc setBuffer:st.initQBuf offset:0 atIndex:5];

                    MTLSize grid = MTLSizeMake(size, 1, 1);
                    NSUInteger tptgMax = st.pso.maxTotalThreadsPerThreadgroup;
                    NSUInteger tptg = threadsRequested ? std::min((NSUInteger)threadsRequested, tptgMax) : tptgMax;
                    if (tptg == 0) tptg = 64; // sane default
                    MTLSize tg = MTLSizeMake(tptg, 1, 1);
                    [enc dispatchThreads:grid threadsPerThreadgroup:tg];
                    [enc endEncoding];
                    [cb commit];
                    [cb waitUntilCompleted];

                    // Inspect results
                    result *res = (result *)[st.resultBuf contents];
                    for (int sc = ERADICATE2_MAX_SCORE; sc > (int)st.scoreMax; --sc) {
                        if (res[sc].found > 0) {
                            st.scoreMax = (uint8_t)sc;
                            if (sc >= (int)globalBest) {
                                globalBest = (uint8_t)sc;
                                printFound(res[sc], (uint8_t)sc, timeStart);
                            }
                            break;
                        }
                    }

                    // Speed update (approx per device per iteration)
                    speed.update(size, st.index);
                }

                // Print speed line periodically
                static unsigned int countPrint = 0;
                if ((++countPrint) % ERADICATE2_SPEEDSAMPLES == 0) {
                    speed.print();
                }
                // NOTE: no quit condition; keep running indefinitely like original
            }
            return 0;
        } catch (std::runtime_error &e) {
            std::cout << "std::runtime_error - " << e.what() << std::endl;
        } catch (...) {
            std::cout << "unknown exception occured" << std::endl;
        }
        return 1;
    }
}
