#include <array>
#include <iomanip>
#include <intrin.h>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string_view>
#include "renderer.hpp"
#include "camera_follow.hpp"
#include <bcrypt.h>
#include "forward_metadata.hpp"
#include "MinHook.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "opengl32.lib")
#pragma comment(lib, "user32.lib")

extern "C" {
FARPROC g_forwards[AVZH_FORWARD_COUNT]{};
void* g_original_sprintf = nullptr;
}
extern "C" void sprintf_entry();

namespace {
static_assert(sizeof(void*) == 4, "x86 game");
constexpr uintptr_t image_base = 0x400000;
constexpr uintptr_t layout_address = 0x487760;
constexpr uintptr_t measure_address = 0x4875e0;
constexpr uintptr_t sprintf_address = 0x4c44b5;
constexpr uintptr_t expand_address = 0x488c30;
constexpr uintptr_t line_height_address = 0x6add7c;
constexpr uintptr_t clip_flag_address = 0x6adbba;
constexpr uintptr_t clip_start_address = 0x6ad5b0;
constexpr uintptr_t clip_end_address = 0x6ad5b4;
constexpr uintptr_t alpha_address = 0x5efe80;
constexpr uintptr_t create_save_folders_address = 0x42eca0;
constexpr uintptr_t documents_address = 0x602f90;
constexpr size_t text_limit = 4096;
constexpr char supported_sha[] = "893d26e896c58d6208eac56275cf961d87b48eb91ad891c5815a5485f2decfa1";

using Layout = void(__cdecl*)(void*, uint32_t, uint32_t, const char*, short, short, short, short, short);
using Measure = short(__cdecl*)(const char*);
using Expand = void(__cdecl*)(char*);
Layout original_layout = nullptr;
Measure original_measure = nullptr;
void (__cdecl* original_save_folders)() = nullptr;
uintptr_t game_base = 0;
std::wstring data_path;
std::string isolated_documents;
INIT_ONCE real_once = INIT_ONCE_STATIC_INIT;
INIT_ONCE adapter_once = INIT_ONCE_STATIC_INIT;
HMODULE system_winmm = nullptr;
thread_local avzh::Renderer renderer;
avzh::FontSettings font_settings;
bool (*original_escape)(int) = nullptr;
void (*original_spatial_update)() = nullptr;
void (*original_world_labels)() = nullptr;
using WalkVector = void(__thiscall*)(void*, int, int, short);
using WalkFallback = unsigned(__thiscall*)(void*, short);
WalkVector original_walk_vector = nullptr;
WalkFallback original_walk_fallback = nullptr;
unsigned movement_percent = 100;
unsigned marker_mode = 0;
avzh::CameraFollow camera_follow;
std::mutex log_mutex;
std::set<uint32_t> consumed;

struct Entry {
    std::string source, target;
    std::unique_ptr<avzh::Dictionary> format;
};
std::unordered_map<uint32_t, Entry> native_strings;
std::unordered_map<uint32_t, std::string> resource_strings;
std::unordered_map<std::string, std::string> actor_names;
struct WideSlot {
    uint32_t rva;
    std::string expected;
    std::wstring replacement;
};
std::vector<WideSlot> wide_slots;

struct FormatCall {
    char* output;
    const Entry* entry;
    uintptr_t resume;
    uint32_t rva;
    std::wstring composed;
};
struct FormattedText {
    std::string original;
    std::wstring translation;
    uint32_t rva;
};
thread_local std::array<FormatCall, 8> format_calls{};
thread_local size_t format_depth = 0;
thread_local std::unordered_map<const char*, FormattedText> formatted_text;

template<class T> T& at(uintptr_t address) {
    return *reinterpret_cast<T*>(game_base + address - image_base);
}

void log(const std::string& description, uint32_t identifier = 0) noexcept {
    try {
        std::lock_guard<std::mutex> lock(log_mutex);
        if (data_path.empty() || (identifier && (consumed.size() >= 128 || !consumed.insert(identifier).second))) return;
        std::ofstream output((data_path + L"\\runtime.log").c_str(), std::ios::app);
        output << description;
        if (identifier) output << " " << std::hex << identifier;
        output << '\n';
    } catch (...) {}
}

std::string executable_hash(const std::wstring& path) {
    std::ifstream input(path.c_str(), std::ios::binary);
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!input || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("Cannot open executable for hashing");
    struct CloseAlgorithm {
        BCRYPT_ALG_HANDLE value;
        ~CloseAlgorithm() { BCryptCloseAlgorithmProvider(value, 0); }
    } close_algorithm{algorithm};
    DWORD object_size = 0, result_size = 0;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
                          sizeof(object_size), &result_size, 0) < 0)
        throw std::runtime_error("SHA256 metadata unavailable");
    std::vector<unsigned char> object(object_size);
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0)
        throw std::runtime_error("Cannot initialize SHA256");
    struct CloseHash {
        BCRYPT_HASH_HANDLE value;
        ~CloseHash() { BCryptDestroyHash(value); }
    } close_hash{hash};
    std::array<unsigned char, 65536> bytes{};
    while (input.read(reinterpret_cast<char*>(bytes.data()), bytes.size()) || input.gcount()) {
        if (BCryptHashData(hash, bytes.data(), static_cast<ULONG>(input.gcount()), 0) < 0)
            throw std::runtime_error("Cannot hash executable");
    }
    std::array<unsigned char, 32> digest{};
    if (input.bad() || BCryptFinishHash(hash, digest.data(), digest.size(), 0) < 0)
        throw std::runtime_error("Cannot finalize executable hash");
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (auto byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}

void load_registry() {
    std::ifstream input((data_path + L"\\resources.bin").c_str(), std::ios::binary);
    auto read = [&](void* data, size_t size) {
        if (!input.read(static_cast<char*>(data), size)) throw std::runtime_error("Truncated resource registry");
    };
    auto integer = [&]() { uint32_t result = 0; read(&result, sizeof(result)); return result; };
    auto string = [&](uint32_t size) {
        if (!size || size > 16384) throw std::runtime_error("Invalid registry string length");
        std::string result(size, '\0');
        read(result.data(), size);
        return result;
    };
    char magic[8];
    read(magic, sizeof(magic));
    if (memcmp(magic, "AV2LOC3", sizeof(magic))) throw std::runtime_error("Registry version mismatch");
    const auto count = integer();
    if (count > 20000) throw std::runtime_error("Registry count limit");
    for (uint32_t i = 0; i < count; ++i) {
        const auto address = integer(), original_length = integer(), translated_length = integer();
        auto original = string(original_length);
        auto translated = string(translated_length);
        if ((address & 0xc0000000) == 0xc0000000) {
            if (!actor_names.emplace(std::move(original), std::move(translated)).second)
                throw std::runtime_error("Duplicate actor name alias");
        } else if ((address & 0xc0000000) == 0x40000000) {
            auto replacement = avzh::utf8(translated);
            if ((address & 1) || replacement.size() * sizeof(wchar_t) != original.size())
                throw std::runtime_error("Invalid wide window text slot");
            wide_slots.push_back({address & 0x3fffffff, std::move(original), std::move(replacement)});
        } else if (address) {
            Entry entry{std::move(original), std::move(translated), nullptr};
            if (address & 0x80000000) {
                entry.format = std::make_unique<avzh::Dictionary>();
                entry.format->add(entry.source, entry.target);
                entry.format->prepare();
            }
            if (!native_strings.emplace(address & 0x7fffffff, std::move(entry)).second)
                throw std::runtime_error("Duplicate native string RVA");
        } else {
            size_t used = 0;
            const auto number = std::stoul(original, &used);
            if (used != original.size() || !number || number > 65535 ||
                !resource_strings.emplace(number, std::move(translated)).second)
                throw std::runtime_error("Duplicate or invalid resource marker");
        }
    }
    if (input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("Trailing registry bytes");
}

void apply_wide_slots(char* image, size_t size) {
    uint32_t last = 0;
    std::sort(wide_slots.begin(), wide_slots.end(),
              [](const WideSlot& a, const WideSlot& b) { return a.rva < b.rva; });
    for (const auto& slot : wide_slots) {
        const size_t end = static_cast<size_t>(slot.rva) + slot.expected.size();
        if (!slot.rva || slot.rva < last || end < slot.rva || end > size || size - end < 2 ||
            memcmp(image + slot.rva, slot.expected.data(), slot.expected.size()) ||
            image[end] || image[end + 1])
            throw std::runtime_error("Wide window text does not match the original image");
        last = static_cast<uint32_t>(end + 2);
    }
    struct WritableSlots {
        struct Region { char* address; size_t size; DWORD original; };
        std::vector<Region> regions;
        ~WritableSlots() {
            for (auto it = regions.rbegin(); it != regions.rend(); ++it) {
                DWORD ignored = 0;
                VirtualProtect(it->address, it->size, it->original, &ignored);
            }
        }
    } writable;
    writable.regions.reserve(wide_slots.size());
    for (const auto& slot : wide_slots) {
        auto* address = image + slot.rva;
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(address, &region, sizeof(region)) ||
            (region.Protect != PAGE_READONLY && region.Protect != PAGE_READWRITE &&
             region.Protect != PAGE_WRITECOPY) ||
            static_cast<size_t>(address - static_cast<char*>(region.BaseAddress)) +
                slot.expected.size() > region.RegionSize)
            throw std::runtime_error("Wide window text is outside a readable data region");
        DWORD original = 0;
        if (!VirtualProtect(address, slot.expected.size(), PAGE_READWRITE, &original))
            throw std::runtime_error("Cannot open wide window text for replacement");
        writable.regions.push_back({address, slot.expected.size(), original});
    }
    for (const auto& slot : wide_slots)
        memcpy(image + slot.rva, slot.replacement.data(), slot.expected.size());
}

std::wstring to_wide(const std::string& value, UINT codepage) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(codepage, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) throw std::runtime_error("Cannot decode game text");
    std::wstring wide(size, L'\0');
    MultiByteToWideChar(codepage, 0, value.data(), static_cast<int>(value.size()), wide.data(), size);
    return wide;
}

std::wstring localized_token(char token, const std::string& source) {
    if (token == 'C') {
        const auto name = actor_names.find(source);
        if (name != actor_names.end()) return avzh::utf8(name->second);
    } else if (token == 'N') {
        for (const auto address : {0x5cd274,0x5cd280,0x5cd288,0x5cd290,0x5cd298,
                                   0x5cd2a0,0x5cd2b0,0x5cd2b8,0x5cd2c4}) {
            const auto name = native_strings.find(address - image_base);
            if (name != native_strings.end() && source == name->second.source)
                return avzh::utf8(name->second.target);
        }
    } else if (token == 'P' || token == 'O') {
        if (source == "he" || source == "his") return token == 'P' ? L"他" : L"他的";
        if (source == "she" || source == "her") return token == 'P' ? L"她" : L"她的";
        if (source == "it" || source == "its") return token == 'P' ? L"它" : L"它的";
        if (source == "they" || source == "their") return token == 'P' ? L"他们" : L"他们的";
    }
    return to_wide(source, 1252);
}

void expand_tokens(std::wstring& target) {
    const auto expand = reinterpret_cast<Expand>(game_base + expand_address - image_base);
    for (const char* name : {"[N]", "[C]", "[P]", "[O]"}) {
        const auto token = to_wide(name, 1252);
        auto position = target.find(token);
        if (position == std::wstring::npos) continue;
        char buffer[1024]{};
        memcpy(buffer, name, 3);
        expand(buffer);
        const auto replacement = localized_token(name[1], buffer);
        while (position != std::wstring::npos) {
            target.replace(position, token.size(), replacement);
            position = target.find(token, position + replacement.size());
        }
    }
}

int digit(wchar_t value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'A' && value <= 'Z') return value - 'A' + 10;
    if (value >= 'a' && value <= 'z') return value - 'a' + 10;
    return -1;
}

bool resolve_markers(std::wstring_view source, std::wstring& target) {
    size_t consumed_bytes = 0;
    for (auto marker = source.find(L'~'); marker != std::wstring_view::npos && marker + 4 < source.size();
         marker = source.find(L'~', marker + 1)) {
        if (source[marker + 4] != '~') continue;
        uint32_t ordinal = 0;
        for (size_t i = 1; i <= 3; ++i) {
            const int part = digit(source[marker + i]);
            if (part < 0) { ordinal = 0; break; }
            ordinal = ordinal * 36 + part;
        }
        const auto resource = resource_strings.find(ordinal);
        if (resource == resource_strings.end()) continue;
        if (!(marker == 1 && source[0] == '$'))
            target.append(source.substr(consumed_bytes, marker - consumed_bytes));
        target += avzh::utf8(resource->second);
        consumed_bytes = marker + 5;
        marker += 4;
        log("resource ordinal", ordinal);
    }
    if (!consumed_bytes) return false;
    target.append(source.substr(consumed_bytes));
    return true;
}

const Entry* copied_ui_entry(uintptr_t buffer, std::string_view source) {
    // Match complete native strings only in the buffers of their observed copy paths.
    const auto lookup = [&](uintptr_t address) -> const Entry* {
        const auto entry = native_strings.find(address - image_base);
        return entry != native_strings.end() && entry->second.source == source ? &entry->second : nullptr;
    };
    if (buffer == 0x6add80 || (buffer >= 0x6ac2e0 && buffer < 0x6ac2e0 + 60 * 0x50 &&
                             (buffer - 0x6ac2e0) % 0x50 == 0)) {
        for (const auto address : {0x5c5e18, 0x5c91fc, 0x5c5f70, 0x5c5fd8}) {
            if (const auto* entry = lookup(address)) return entry;
        }
        return nullptr;
    }
    if (buffer >= 0x6a7bf8 && buffer < 0x6a7bf8 + 32 * 0x200 &&
        (buffer - 0x6a7bf8) % 0x200 == 0) return lookup(0x5cd178);
    if (buffer != 0x6abc68 && buffer != 0x6abe68 && buffer != 0x6ac068) return nullptr;
    constexpr uintptr_t tutorial[] = {
        0x5c2d00, 0x5c2da8, 0x5c2e28, 0x5c2e98, 0x5c2f00, 0x5c2f58, 0x5c2fc0,
        0x5c3020, 0x5c30b0, 0x5c3198, 0x5c3220, 0x5c32b8, 0x5c3350, 0x5c33b0,
        0x5c3438, 0x5c34a0, 0x5c34f0, 0x5c35a0, 0x5c3608, 0x5c3640, 0x5c3688,
        0x5c3720, 0x5c3790, 0x5c3818, 0x5c38c0, 0x5c3950, 0x5c3a00,
    };
    for (const auto address : tutorial) {
        if (const auto* entry = lookup(address)) return entry;
    }
    return nullptr;
}

bool localize(const char* input, std::wstring& target) {
    if (!input) return false;
    const auto formatted = formatted_text.find(input);
    const auto pointer = reinterpret_cast<uintptr_t>(input);
    const auto native = pointer >= game_base ? native_strings.find(pointer - game_base) : native_strings.end();
    if (formatted != formatted_text.end() && formatted->second.original == input) {
        target = formatted->second.translation;
        log("formatted native RVA", formatted->second.rva);
    } else if (native != native_strings.end() && native->second.source == input) {
        target = avzh::utf8(native->second.target);
        log("native RVA", native->first);
    } else {
        const auto length = strnlen(input, text_limit + 1);
        if (length > text_limit) return false;
        if (const auto* entry = pointer >= game_base
                ? copied_ui_entry(image_base + pointer - game_base, std::string_view(input, length)) : nullptr) {
            target = avzh::utf8(entry->target);
        } else if (!resolve_markers(to_wide(std::string(input, length), 1252), target)) {
            return false;
        }
    }
    expand_tokens(target);
    std::wstring resolved;
    if (resolve_markers(target, resolved)) target = std::move(resolved);
    return true;
}

int x(uint32_t packed) { return static_cast<int16_t>(packed >> 16); }
int y(uint32_t packed) { return static_cast<int16_t>(packed & 0xffff); }
short native_short(int value) { return static_cast<short>(std::clamp(value, -32768, 32767)); }

bool ascii_word(wchar_t c) {
    return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9');
}

bool break_before(wchar_t prior, wchar_t next) {
    constexpr std::wstring_view opening = L"（《「『【〔“‘(";
    if (avzh::closing(next) || opening.find(prior) != std::wstring_view::npos) return false;
    if (prior == L' ' && ascii_word(next)) return true;
    return prior >= 0x2e80 || next >= 0x2e80;
}

std::vector<std::wstring> wrap_chinese(const std::wstring& text, int width, int step) {
    std::vector<std::wstring> lines;
    size_t begin = 0;
    while (true) {
        const auto separator = text.find_first_of(L"|\r\n", begin);
        const auto end = separator == std::wstring::npos ? text.size() : separator;
        if (begin == end) lines.emplace_back();
        while (begin < end) {
            size_t position = begin, preferred = begin;
            while (position < end) {
                size_t following = position + 1;
                if (text[position] >= 0xd800 && text[position] <= 0xdbff && following < end &&
                    text[following] >= 0xdc00 && text[following] <= 0xdfff) ++following;
                if (renderer.measure(text.substr(begin, following - begin), step) > width && position > begin)
                    break;
                position = following;
                if (position < end && break_before(text[position - 1], text[position])) preferred = position;
            }
            if (position < end && preferred > begin) position = preferred;
            auto line = text.substr(begin, position - begin);
            while (!line.empty() && line.back() == L' ') line.pop_back();
            lines.push_back(std::move(line));
            begin = position;
            while (begin < end && text[begin] == L' ') ++begin;
        }
        if (separator == std::wstring::npos) break;
        begin = separator + 1;
        if (text[separator] == L'\r' && begin < text.size() && text[begin] == L'\n') ++begin;
    }
    return lines;
}

struct Projection {
    GLint prior = GL_MODELVIEW;
    Projection(int width, int height) {
        glGetIntegerv(GL_MATRIX_MODE, &prior);
        glMatrixMode(GL_PROJECTION);
        glPushMatrix();
        glLoadIdentity();
        glOrtho(0, width, 0, height, -1, 1);
        glMatrixMode(GL_MODELVIEW);
        glPushMatrix();
        glLoadIdentity();
    }
    ~Projection() {
        glMatrixMode(GL_MODELVIEW);
        glPopMatrix();
        glMatrixMode(GL_PROJECTION);
        glPopMatrix();
        glMatrixMode(prior);
    }
};

bool render(uint32_t first, uint32_t last, const char* text, short align, short font,
            short red, short green, short blue) {
    const auto dc = wglGetCurrentDC();
    RECT client{};
    if (!dc || !GetClientRect(WindowFromDC(dc), &client)) return false;
    avzh::TextState state;
    state.settings = font_settings;
    const auto composed = formatted_text.find(text);
    if (composed != formatted_text.end() && composed->second.original == text &&
        (composed->second.rva == 0x5cda44 - image_base || composed->second.rva == 0x5cda4c - image_base))
        state.settings.percent = 100; // The keyboard menu uses fixed-height rows.
    state.screen_width = client.right;
    state.screen_height = client.bottom;
    state.left = x(first);
    state.top = y(first);
    state.right = x(last);
    state.bottom = y(last);
    if (state.screen_width <= 0 || state.screen_height <= 0 || (align != 2 && state.right <= state.left))
        return false;
    std::wstring wide;
    if (!localize(text, wide)) return false;
    state.align = align;
    state.font = font;
    state.red = red / 31.0f;
    state.green = green / 31.0f;
    state.blue = blue / 31.0f;
    state.alpha = at<float>(alpha_address);
    state.clip = at<unsigned char>(clip_flag_address) == 0;
    state.clip_left = x(at<uint32_t>(clip_start_address));
    state.clip_top = y(at<uint32_t>(clip_start_address));
    state.clip_right = x(at<uint32_t>(clip_end_address));
    state.clip_bottom = y(at<uint32_t>(clip_end_address));
    Projection projection(state.screen_width, state.screen_height);
    avzh::TextResult result;
    if (align == 0 || (align == 2 && wide.find_first_of(L"|\r\n") != std::wstring::npos)) {
        const int width = std::max(1, state.right - state.left - 6);
        const int step = state.settings.step(font);
        state.align = 2;
        for (auto& line : wrap_chinese(wide, width, step)) {
            const auto drawn = renderer.draw(std::move(line), state);
            result.last_x = drawn.last_x;
            result.last_y = drawn.last_y;
            result.height += step;
            state.top += step;
        }
    } else {
        result = renderer.draw(std::move(wide), state);
    }
    at<short>(line_height_address) = native_short(result.height);
    at<short>(0x6ae18c) = native_short(result.last_x);
    at<short>(0x6ae190) = native_short(result.last_y);
    return true;
}

void __cdecl layout_hook(void* destination, uint32_t first, uint32_t last, const char* text,
                         short align, short font, short red, short green, short blue) noexcept {
    try {
        if (render(first, last, text, align, font, red, green, blue)) return;
    } catch (const std::exception& error) { log(error.what()); }
    original_layout(destination, first, last, text, align, font, red, green, blue);
}

short __cdecl measure_hook(const char* source) noexcept {
    try {
        std::wstring target;
        if (localize(source, target)) {
            int longest = 0;
            size_t begin = 0;
            for (auto end = target.find_first_of(L"|\r\n"); end != std::wstring::npos;
                 end = target.find_first_of(L"|\r\n", begin)) {
                longest = std::max(longest, renderer.measure(target.substr(begin, end - begin), font_settings.step(12)));
                begin = end + 1;
            }
            longest = std::max(longest, renderer.measure(target.substr(begin), font_settings.step(12)));
            return native_short(longest);
        }
    } catch (const std::exception& error) { log(error.what()); }
    return original_measure(source);
}

void __cdecl isolate_save_folders() {
    memcpy(&at<char>(documents_address), isolated_documents.c_str(), isolated_documents.size() + 1);
    original_save_folders();
    log("Test preferences and saves redirected");
}

void prepare_test_documents() {
    const auto flag = GetFileAttributesW((data_path + L"\\isolated-save.flag").c_str());
    if (flag == INVALID_FILE_ATTRIBUTES) return;
    const auto directory = data_path + L"\\TestDocuments";
    if (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Cannot create isolated test save directory");
    char path[200]{};
    BOOL replacement = FALSE;
    if (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, directory.c_str(), -1, path,
                             sizeof(path), nullptr, &replacement) || replacement)
        throw std::runtime_error("Unsupported isolated test save path");
    isolated_documents = path;
}

bool __declspec(noinline) inventory_escape(int input) {
    if (original_escape(input)) return true;
    // Observe only the Escape check inside the native inventory close branch.
    if (reinterpret_cast<uintptr_t>(_ReturnAddress()) != game_base + 0x6dd87 ||
        at<short>(0x6ae198) != 10) return false;
    using MatchBinding = bool(__cdecl*)(int, short);
    return reinterpret_cast<MatchBinding>(game_base + 0x355f0)(input, 3);
}

bool foreground_game() {
    DWORD process = 0;
    GetWindowThreadProcessId(GetForegroundWindow(), &process);
    return process == GetCurrentProcessId();
}

bool call_targets(uintptr_t site, uintptr_t entry) {
    const auto* bytes = &at<unsigned char>(site);
    int32_t displacement = 0;
    memcpy(&displacement, bytes + 1, sizeof(displacement));
    return bytes[0] == 0xe8 && static_cast<intptr_t>(site + 5) + displacement == static_cast<intptr_t>(entry);
}

template<size_t N>
bool install_optional_hook(uintptr_t entry, const unsigned char (&signature)[N], bool call_verified,
                           void* detour, void** original, const char* feature) {
    auto* address = &at<unsigned char>(entry);
    if (!call_verified || memcmp(address, signature, N)) {
        log(std::string(feature) + ": signature mismatch");
        return false;
    }
    const auto status = MH_CreateHook(address, detour, original);
    log(std::string(feature) + ": " + MH_StatusToString(status));
    return status == MH_OK;
}

bool party_exploration_actor(const void* actor) {
    const auto base = game_base + 0x46c298;
    const auto offset = reinterpret_cast<uintptr_t>(actor) - base;
    return at<short>(0x6ae194) == 10 && offset < 8 * 0x19b4 && !(offset % 0x19b4);
}

short scaled_speed(short speed) {
    if (speed <= 0) return speed;
    return static_cast<short>(std::min(32767u, (speed * movement_percent + 50u) / 100u));
}

__declspec(noinline) void __fastcall walk_vector(void* position, void*, int x, int y, short speed) {
    const auto caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    if (caller != game_base + 0x5030b ||
        !party_exploration_actor(static_cast<unsigned char*>(position) - 0x20)) {
        original_walk_vector(position, x, y, speed);
        return;
    }
    original_walk_vector(position, x, y, scaled_speed(speed));
    *reinterpret_cast<short*>(static_cast<unsigned char*>(position) + 0x12) = speed;
}

__declspec(noinline) unsigned __fastcall walk_fallback(void* actor, void*, short axis) {
    const auto caller = reinterpret_cast<uintptr_t>(_ReturnAddress()) - game_base;
    if ((caller != 0x505ac && caller != 0x505c4 && caller != 0x505d6 && caller != 0x505ee) ||
        !party_exploration_actor(actor)) return original_walk_fallback(actor, axis);
    auto& speed = *reinterpret_cast<short*>(static_cast<unsigned char*>(actor) + 0x32);
    const short normal = speed;
    speed = scaled_speed(normal);
    const auto result = original_walk_fallback(actor, axis);
    speed = normal;
    return result;
}

uint32_t screen_point(int x, int y) {
    return static_cast<uint32_t>(static_cast<uint16_t>(x)) << 16 | static_cast<uint16_t>(y);
}

void draw_markers() {
    const short mode = at<short>(0x6ae194);
    if ((mode != 10 && mode != 15) || at<short>(0x6ae198) ||
        at<unsigned char>(0x6adca3) || at<unsigned char>(0x6adcc3) ||
        (marker_mode == 1 && !at<unsigned char>(0x6adcae)) || !foreground_game()) return;
    const auto clip_start = at<uint32_t>(0x6ad5c0);
    const auto clip_end = at<uint32_t>(0x6ad5c4);
    const int left = static_cast<short>(clip_start >> 16), top = static_cast<short>(clip_start);
    const int right = static_cast<short>(clip_end >> 16), bottom = static_cast<short>(clip_end);
    constexpr int width = 22, height = 28;
    if (right - left < width || bottom - top < height) return;

    using ObjectPredicate = unsigned(__thiscall*)(const void*);
    using VisibleTile = short(__cdecl*)(short, short);
    using LineOfSight = unsigned(__cdecl*)(int, int, int, int, short);
    using Draw = void(__cdecl*)(int, uint32_t, uint32_t, uint32_t, uint32_t, float, float, float, float);
    const auto current = reinterpret_cast<ObjectPredicate>(game_base + 0x406e0);
    const auto interactive = reinterpret_cast<ObjectPredicate>(game_base + 0x41b50);
    const auto visible = reinterpret_cast<VisibleTile>(game_base + 0x38320);
    const auto in_sight = reinterpret_cast<LineOfSight>(game_base + 0x10fe0);
    const auto draw = reinterpret_cast<Draw>(game_base + 0xddc0);
    auto rect = [&](int x, int y, int w, int h, float red, float green, float blue) {
        draw(0, screen_point(x, y), screen_point(x + w, y + h), clip_start, clip_end, red, green, blue, 1.0f);
    };
    for (int index = 0; index < 1200; ++index) {
        const int item = at<int>(0x6a4350 + index * 4);
        if (item < 9000 || item >= 9600) continue;
        const auto object = 0x9dda50 + (item - 9000) * 0x490;
        const int x0 = at<short>(object + 0x3a), y0 = at<short>(object + 0x38);
        const int x1 = at<short>(object + 0x3e), y1 = at<short>(object + 0x3c);
        if (x0 >= x1 || y0 >= y1 || x1 <= left || x0 >= right || y1 <= top || y0 >= bottom) continue;
        const auto* instance = &at<unsigned char>(object);
        if (at<short>(object + 4) || !(current(instance) & 0xff) || !(interactive(instance) & 0xff) ||
            visible(at<short>(object + 0x14), at<short>(object + 0x18)) <= 0 ||
            !(in_sight(at<int>(object + 0x28), at<int>(object + 0x2c),
                       at<int>(object + 0x30), at<int>(object + 0x34), 1) & 0xff)) continue;
        const int x = std::clamp((x0 + x1) / 2 - width / 2, left, right - width);
        const int y = std::clamp(y0 + 2, top, bottom - height);
        rect(x, y, width, height, 1, 1, 1);
        rect(x + 2, y + 2, 18, 24, 31, 27, 5);
        rect(x + 9, y + 5, 4, 11, 1, 1, 1);
        rect(x + 9, y + 19, 4, 4, 1, 1, 1);
    }
}

void __declspec(noinline) world_labels() {
    if (reinterpret_cast<uintptr_t>(_ReturnAddress()) == game_base + 0x317bf) draw_markers();
    original_world_labels();
}

avzh::CameraActor sample_camera_actor(uintptr_t actor, bool active, short layer) {
    avzh::CameraActor sample;
    sample.x = at<int>(actor + 0x20);
    sample.y = at<int>(actor + 0x24);
    sample.motion = at<short>(actor + 0x157c) == 1 ? 1 : 0;
    sample.valid = active && at<short>(actor + 0x30) == layer &&
        sample.x >= 0 && sample.y >= 0 && sample.x <= 32768 && sample.y <= 32768;
    return sample;
}

void __declspec(noinline) camera_spatial_update() {
    if (reinterpret_cast<uintptr_t>(_ReturnAddress()) == game_base + 0x6cf2d) {
        avzh::CameraFrame frame;
        frame.mode = at<short>(0x6ae194);
        frame.layer = at<short>(0x86583c);
        frame.tick = at<uint32_t>(0x6add18);
        frame.allowed = (frame.mode == 10 || frame.mode == 15) && !at<short>(0x6ae198) &&
            !at<unsigned char>(0x6adcc3) && foreground_game() && frame.layer >= 0 && frame.layer < 2;
        if (frame.allowed) {
            if (frame.mode == 15)
                frame.preferred = reinterpret_cast<short(__cdecl*)()>(game_base + 0x5fe20)();
            using ActiveActor = unsigned(__cdecl*)(short);
            const auto active = reinterpret_cast<ActiveActor>(game_base + 0x5fc60);
            for (short index = 0; index < 2; ++index) {
                const auto actor = 0x86c298 + index * 0x19b4;
                frame.actors[index] = sample_camera_actor(actor, (active(index) & 0xff) != 0, frame.layer);
            }
        }
        const auto target = camera_follow.update(frame);
        if (target.follow)
            reinterpret_cast<void(__cdecl*)(int, int)>(game_base + 0x3c350)(target.x, target.y);
    }
    original_spatial_update();
}

BOOL CALLBACK initialize_adapter(PINIT_ONCE, void*, void**) noexcept {
    try {
        wchar_t executable[MAX_PATH]{};
        const auto length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
        if (!length || length == MAX_PATH) return TRUE;
        const std::wstring path(executable);
        data_path = path.substr(0, path.find_last_of(L"\\/")) + L"\\Avadon2Chinese";
        if (executable_hash(path) != supported_sha) throw std::runtime_error("Unsupported executable");
        game_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        load_registry();
        const auto settings_path = data_path + L"\\font.ini";
        font_settings = avzh::FontSettings::load(settings_path);
        prepare_test_documents();
        auto* layout = &at<unsigned char>(layout_address);
        auto* measure = &at<unsigned char>(measure_address);
        auto* formatter = &at<unsigned char>(sprintf_address);
        const unsigned char layout_start[] = {0x55,0x8b,0xec,0x81,0xec,0x80,0x08,0,0};
        const unsigned char measure_start[] = {0x55,0x8b,0xec,0x81,0xec,0x30,0x04,0,0};
        const unsigned char sprintf_start[] = {0x8b,0xff,0x55,0x8b,0xec,0x83,0xec,0x20};
        if (memcmp(layout, layout_start, sizeof(layout_start)) || memcmp(measure, measure_start, sizeof(measure_start))
            || memcmp(formatter, sprintf_start, sizeof(sprintf_start)))
            throw std::runtime_error("Unexpected entry prologue");
        MH_STATUS status = MH_Initialize();
        if (status == MH_OK)
            status = MH_CreateHook(layout, reinterpret_cast<void*>(&layout_hook), reinterpret_cast<void**>(&original_layout));
        if (status == MH_OK)
            status = MH_CreateHook(measure, reinterpret_cast<void*>(&measure_hook), reinterpret_cast<void**>(&original_measure));
        if (status == MH_OK)
            status = MH_CreateHook(formatter, reinterpret_cast<void*>(&sprintf_entry), &g_original_sprintf);
        if (status == MH_OK) {
            const auto setting = [&](const wchar_t* section, const wchar_t* key, int fallback) {
                return GetPrivateProfileIntW(section, key, fallback, settings_path.c_str());
            };
            if (setting(L"Inventory", L"ToggleHotkey", 0)) {
                const unsigned char signature[] = {0x55,0x8b,0xec,0x83,0x7d,0x08,0x18};
                install_optional_hook(0x435010, signature, call_targets(0x46dd82, 0x435010),
                    reinterpret_cast<void*>(&inventory_escape), reinterpret_cast<void**>(&original_escape),
                    "Inventory toggle");
            }
            if (setting(L"Camera", L"FollowCharacter", 0)) {
                const unsigned char signature[] = {0x55,0x8b,0xec,0x81,0xec,0xb4,0,0,0};
                install_optional_hook(0x43c550, signature, call_targets(0x46cf28, 0x43c550),
                    reinterpret_cast<void*>(&camera_spatial_update), reinterpret_cast<void**>(&original_spatial_update),
                    "Camera follow");
            }
            marker_mode = std::min(2u, setting(L"Interaction", L"HighlightOnShift", 0));
            if (marker_mode) {
                const unsigned char signature[] = {0x55,0x8b,0xec,0x83,0xec,0x38};
                install_optional_hook(0x43f620, signature, call_targets(0x4317ba, 0x43f620),
                    reinterpret_cast<void*>(&world_labels), reinterpret_cast<void**>(&original_world_labels),
                    "Interaction markers");
            }
            movement_percent = std::clamp(setting(L"Movement", L"SpeedPercent", 100), 100u, 200u);
            if (movement_percent > 100) {
                const unsigned char vector_signature[] = {0x55,0x8b,0xec,0x83,0xec,0x08,0x56};
                const unsigned char fallback_signature[] = {0x55,0x8b,0xec,0x83,0xec,0x2c,0x56};
                if (install_optional_hook(0x463610, vector_signature, call_targets(0x450306, 0x463610),
                    reinterpret_cast<void*>(&walk_vector), reinterpret_cast<void**>(&original_walk_vector),
                    "Exploration movement vector") &&
                    !install_optional_hook(0x451090, fallback_signature,
                        call_targets(0x4505a7, 0x451090) && call_targets(0x4505bf, 0x451090) &&
                        call_targets(0x4505d1, 0x451090) && call_targets(0x4505e9, 0x451090),
                        reinterpret_cast<void*>(&walk_fallback), reinterpret_cast<void**>(&original_walk_fallback),
                        "Exploration movement fallback")) {
                    MH_RemoveHook(&at<unsigned char>(0x463610));
                }
            }
        }
        if (status == MH_OK && !isolated_documents.empty()) {
            auto* save_folders = &at<unsigned char>(create_save_folders_address);
            const unsigned char save_start[] = {0x55,0x8b,0xec,0x81,0xec,0x50,0x01,0,0};
            if (memcmp(save_folders, save_start, sizeof(save_start)))
                throw std::runtime_error("Unexpected save folder initializer prologue");
            status = MH_CreateHook(save_folders, reinterpret_cast<void*>(&isolate_save_folders),
                                   reinterpret_cast<void**>(&original_save_folders));
        }
        if (status == MH_OK) status = MH_EnableHook(MH_ALL_HOOKS);
        if (status != MH_OK) {
            MH_Uninitialize();
            throw std::runtime_error(MH_StatusToString(status));
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(game_base);
        const auto* pe = reinterpret_cast<const IMAGE_NT_HEADERS32*>(game_base + dos->e_lfanew);
        try {
            apply_wide_slots(reinterpret_cast<char*>(game_base), pe->OptionalHeader.SizeOfImage);
            log("Wide window text active: " + std::to_string(wide_slots.size()));
        } catch (const std::exception& error) {
            log(std::string("Wide window text fallback: ") + error.what());
        }
        log("Hooks active: " + std::to_string(resource_strings.size()) + " resources, "
            + std::to_string(native_strings.size()) + " native strings");
    } catch (const std::exception& error) { log(std::string("Initialization failed: ") + error.what()); }
    return TRUE;
}

BOOL CALLBACK initialize_system(PINIT_ONCE, void*, void**) noexcept {
    wchar_t system[MAX_PATH]{};
    if (!GetSystemDirectoryW(system, MAX_PATH)) return FALSE;
    const auto path = std::wstring(system) + L"\\winmm.dll";
    system_winmm = LoadLibraryW(path.c_str());
    if (!system_winmm) return FALSE;
    for (unsigned i = 0; i < AVZH_FORWARD_COUNT; ++i)
        g_forwards[i] = GetProcAddress(system_winmm, avzh_forward_names[i] ? avzh_forward_names[i] :
                                       MAKEINTRESOURCEA(avzh_forward_ordinals[i]));
    return TRUE;
}

DWORD WINAPI bootstrap(void*) noexcept {
    InitOnceExecuteOnce(&adapter_once, initialize_adapter, nullptr, nullptr);
    return 0;
}
}

std::wstring display_argument(const char* argument) {
    std::wstring result;
    if (!argument || !*argument) return result;
    if (localize(argument, result)) return result;
    return to_wide(argument, 1252);
}

std::wstring compose_display(uintptr_t caller, const char* format, const uintptr_t* arguments,
                             const Entry* entry) {
    if (caller == 0x48b5e9 && strcmp(format, "%s") == 0) {
        std::wstring result;
        localize(reinterpret_cast<const char*>(arguments[0]), result);
        return result;
    }
    if (caller == 0x4030f4 && strcmp(format, "%s%s") == 0)
        return display_argument(reinterpret_cast<const char*>(arguments[0])) +
               display_argument(reinterpret_cast<const char*>(arguments[1]));
    if (caller == 0x449292 && strcmp(format, "%s %s") == 0)
        return display_argument(reinterpret_cast<const char*>(arguments[0])) + L" " +
               display_argument(reinterpret_cast<const char*>(arguments[1]));
    if (caller == 0x4293e2 && strcmp(format, "%s - %s") == 0) {
        auto key = display_argument(reinterpret_cast<const char*>(arguments[1]));
        if (key == L"Space") key = L"空格";
        return display_argument(reinterpret_cast<const char*>(arguments[0])) + L" - " + key;
    }
    if (caller == 0x425627) {
        const auto ending = native_strings.find(0x5c52d8 - image_base);
        const auto choice = reinterpret_cast<const char*>(arguments[1]);
        if (strcmp(format, "%d. %s") == 0 && ending != native_strings.end() &&
            choice && ending->second.source == choice && arguments[0] > 0 && arguments[0] <= 8)
            return std::to_wstring(arguments[0]) + L". " + avzh::utf8(ending->second.target);
        return {};
    }
    if (!entry) return {};
    switch (caller) {
    case 0x429409: // Shortcut currently being edited.
    case 0x449e02: case 0x449f03: // Basic attack names.
    case 0x449229: case 0x44926e: // Weight with quantity or charges.
    case 0x40345d: case 0x403491: case 0x403579: case 0x4035d7: case 0x403647:
        break;
    default: return {};
    }
    std::wstring result;
    std::size_t argument = 0;
    for (const auto& part : avzh::format_parts(entry->target)) {
        result += avzh::utf8(part.literal);
        if (part.spec.empty()) continue;
        if (argument == 3) return {};
        if (part.spec == "%s")
            result += display_argument(reinterpret_cast<const char*>(arguments[argument]));
        else if (part.spec == "%d")
            result += std::to_wstring(static_cast<int>(arguments[argument]));
        else return {};
        ++argument;
    }
    return result;
}

extern "C" bool __cdecl begin_sprintf(const char* format, char* output, uintptr_t resume,
                                     const uintptr_t* arguments) noexcept {
    if (!output) return false;
    formatted_text.erase(output);
    const auto address = reinterpret_cast<uintptr_t>(format);
    if (address < game_base || format_depth == format_calls.size()) return false;
    const auto rva = address - game_base;
    const auto entry = native_strings.find(rva);
    const auto record = entry != native_strings.end() && entry->second.source == format ? &entry->second : nullptr;
    try {
        auto composed = compose_display(resume - game_base + image_base, format, arguments, record);
        if (!record && composed.empty()) return false;
        format_calls[format_depth++] = {output, record, resume, rva, std::move(composed)};
        return true;
    } catch (...) { return false; }
}

std::wstring inventory_title(const Entry& entry, const std::string& original) {
    constexpr std::string_view suffix = " Inventory:";
    const auto substitution = entry.target.find("%s");
    if (entry.source != "%s Inventory:" || substitution == std::string::npos ||
        original.size() <= suffix.size() ||
        std::string_view(original).substr(original.size() - suffix.size()) != suffix) return {};
    const auto name = original.substr(0, original.size() - suffix.size());
    const auto default_name = native_strings.find(0x5cd280 - image_base);
    const auto display_name = default_name != native_strings.end() && name == default_name->second.source
        ? avzh::utf8(default_name->second.target) : to_wide(name, 1252);
    return avzh::utf8(entry.target.substr(0, substitution)) + display_name +
           avzh::utf8(entry.target.substr(substitution + 2));
}

extern "C" uintptr_t __cdecl finish_sprintf(int length) noexcept {
    auto call = std::move(format_calls[--format_depth]);
    try {
        if (length > 0 && length <= static_cast<int>(text_limit)) {
            std::string original(call.output, length);
            std::string translation;
            if (call.composed.empty() && call.entry) {
                if (call.rva != 0x5cb094 - image_base && call.entry->format)
                    call.entry->format->lookup(original, translation);
                else if (original == call.entry->source)
                    translation = call.entry->target;
            }
            auto display = !call.composed.empty() ? std::move(call.composed) : call.rva == 0x5cb094 - image_base && call.entry
                ? inventory_title(*call.entry, original) : avzh::utf8(translation);
            if (!display.empty()) {
                if (formatted_text.size() >= 128) formatted_text.clear();
                formatted_text.insert_or_assign(call.output,
                    FormattedText{std::move(original), std::move(display), call.rva});
            }
        }
    } catch (...) {}
    return call.resume;
}

// Call the game's variadic formatter with its original stack and arguments.
// Only observed translations are kept for the display hooks, never written to the game buffer.
extern "C" __declspec(naked) void sprintf_return() {
    __asm {
        lea esp, [esp-4]
        pushfd
        pushad
        push eax
        call finish_sprintf
        add esp, 4
        mov [esp+36], eax
        popad
        popfd
        ret
    }
}

extern "C" __declspec(naked) void sprintf_entry() {
    __asm {
        pushfd
        pushad
        mov eax, [esp+44]
        mov edx, [esp+40]
        mov ecx, [esp+36]
        lea ebx, [esp+48]
        push ebx
        push ecx
        push edx
        push eax
        call begin_sprintf
        add esp, 16
        test al, al
        jz forward_original
        mov dword ptr [esp+36], offset sprintf_return
    forward_original:
        popad
        popfd
        jmp dword ptr [g_original_sprintf]
    }
}

extern "C" void __cdecl ResolveForward(unsigned index) noexcept {
    if (!InitOnceExecuteOnce(&real_once, initialize_system, nullptr, nullptr) ||
        index >= AVZH_FORWARD_COUNT || !g_forwards[index]) ExitProcess(ERROR_PROC_NOT_FOUND);
}

extern "C" DWORD WINAPI ProxyClock() {
    ResolveForward(AVZH_CLOCK_INDEX);
    InitOnceExecuteOnce(&adapter_once, initialize_adapter, nullptr, nullptr);
    return reinterpret_cast<DWORD(WINAPI*)()>(g_forwards[AVZH_CLOCK_INDEX])();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        const auto thread = CreateThread(nullptr, 0, bootstrap, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}

#include "forward_stubs.inc"

#ifdef AV2_OFFLINE_TEST
#include <cstdarg>
#include <cstdio>

int __cdecl fixture_formatter(char* output, const char* format, ...) {
    va_list arguments;
    va_start(arguments, format);
    const int length = vsnprintf(output, 128, format, arguments);
    va_end(arguments);
    return length;
}

int wmain(int count, wchar_t** arguments) {
    if (count != 2) return 1;
    data_path = arguments[1];
    load_registry();
    if (native_strings.empty() || resource_strings.empty() || wide_slots.size() != 7) return 2;
    data_path.clear();
    std::vector<char> game_fixture(0x2b0000);
    game_base = reinterpret_cast<uintptr_t>(game_fixture.data());
    // Distinguish the actor's original name storage from the native layer field.
    constexpr uintptr_t actor_fixture = 0x600000;
    at<short>(actor_fixture + 0x10) = 'm';
    at<short>(actor_fixture + 0x30) = 1;
    at<int>(actor_fixture + 0x20) = 1000;
    at<int>(actor_fixture + 0x24) = 2400;
    at<short>(actor_fixture + 0x157c) = 1;
    const auto moving_actor = sample_camera_actor(actor_fixture, true, 1);
    if (!moving_actor.valid || moving_actor.x != 1000 || moving_actor.y != 2400 || !moving_actor.motion ||
        sample_camera_actor(actor_fixture, true, 0).valid ||
        sample_camera_actor(actor_fixture, false, 1).valid) return 38;
    const auto fixture_text = [&](uintptr_t address, uintptr_t buffer) {
        char* copy = &at<char>(buffer);
        const auto& entry = native_strings.at(address - image_base);
        memcpy(copy, entry.source.c_str(), entry.source.size() + 1);
        return copy;
    };
    std::wstring result;
    for (const auto address : {0x5ccc4cu, 0x5ccc54u, 0x5cc86cu, 0x5cc9fcu}) {
        const bool male = address == 0x5ccc4c || address == 0x5ccc54;
        const char* label = fixture_text(address, address);
        if (strcmp(label, male ? "Male" : "Female") || !localize(label, result) ||
            result != (male ? L"男性" : L"女性")) return 39;
    }
    for (const auto address : {0x5c5e18u, 0x5c2da8u, 0x5c2e28u, 0x5c2fc0u,
                              0x5c3020u, 0x5c30b0u, 0x5c3a00u, 0x5cd178u}) {
        const auto buffer = address == 0x5c5e18 ? 0x6add80u :
                            address == 0x5cd178 ? 0x6a7bf8u + 31 * 0x200 : 0x6abe68u;
        if (!localize(fixture_text(address, buffer), result) ||
            result != avzh::utf8(native_strings.at(address - image_base).target) ||
            localize(fixture_text(address, buffer + 1), result)) return 21;
    }
    g_original_sprintf = reinterpret_cast<void*>(&fixture_formatter);
    using Format = int(__cdecl*)(char*, const char*, ...);
    const auto format = reinterpret_cast<Format>(&sprintf_entry);
    const char* inventory = fixture_text(0x5cb094, 0x5cb094);
    char output[128]{};
    const auto& translated_title = native_strings.at(0x5cb094 - image_base).target;
    const auto expected_title = [&](const std::string& name) {
        auto text = translated_title;
        return avzh::utf8(text.replace(text.find("%s"), 2, name));
    };
    format(output, inventory, "Raidon");
    if (strcmp(output, "Raidon Inventory:") || !localize(output, result) ||
        result != expected_title(native_strings.at(0x5cd280 - image_base).target)) return 22;
    format(output, inventory, "Jos\xe9");
    if (strcmp(output, "Jos\xe9 Inventory:") || !localize(output, result) ||
        result != expected_title("José")) return 23;
    if (localized_token('C', "Silke") != L"西尔克" || localized_token('N', "Tristram") != L"特里斯特拉姆" ||
        localized_token('N', "My Adventurer") != L"My Adventurer" ||
        localized_token('P', "she") != L"她" || localized_token('O', "her") != L"她的") return 24;
    const auto greeting = avzh::utf8(resource_strings.at(12607));
    const auto departure = avzh::utf8(resource_strings.at(12637));
    const auto speech_begin = greeting.find(L'“');
    const auto speech_end = greeting.find(L'”');
    const auto player_token = greeting.find(L"[N]");
    const auto departure_end = departure.find(L'”');
    const auto pronoun_token = departure.find(L"[P]");
    if (speech_begin == std::wstring::npos || speech_end == std::wstring::npos ||
        player_token == std::wstring::npos || !(speech_begin < player_token && player_token < speech_end) ||
        departure.empty() || departure.front() != L'“' || departure_end == std::wstring::npos ||
        pronoun_token == std::wstring::npos || departure_end >= pronoun_token ||
        greeting.find(L'_') != std::wstring::npos || departure.find(L'_') != std::wstring::npos) return 25;
    const auto address_arg = [](const char* text) { return reinterpret_cast<uintptr_t>(text); };
    const auto scoped_format = [&](uintptr_t caller, const char* input, uintptr_t first, uintptr_t second,
                                   uintptr_t third, const wchar_t* expected) {
        uintptr_t args[] = {first, second, third};
        const auto resume = game_base + caller - image_base;
        if (!begin_sprintf(input, output, resume, args)) return false;
        const auto length = caller == 0x425627
            ? fixture_formatter(output, input, static_cast<int>(first), reinterpret_cast<const char*>(second))
            : fixture_formatter(output, input, reinterpret_cast<const char*>(first),
                                reinterpret_cast<const char*>(second), reinterpret_cast<const char*>(third));
        return finish_sprintf(length) == resume && localize(output, result) &&
               result.find(expected) != std::wstring::npos;
    };
    const auto* end = fixture_text(0x5c52d8, 0x5c52d8);
    auto* numbered = &at<char>(0x5cd54c);
    memcpy(numbered, "%d. %s", sizeof("%d. %s"));
    if (!scoped_format(0x425627, numbered, 1, address_arg(end), 0, L"1. 对话结束。")) return 26;
    auto* melee = fixture_text(0x5ce918, 0x5ce918);
    auto* physical = fixture_text(0x5efea0, 0x5efea0);
    auto* damage = fixture_text(0x5cea24, 0x5cea24);
    if (!scoped_format(0x449e02, fixture_text(0x5c8640,0x5c8640), address_arg(melee),0,0,L"基础攻击：近战攻击") ||
        !scoped_format(0x403491, damage, address_arg("7-21"), address_arg(physical), address_arg(""), L"7-21 物理 伤害。"))
        return 27;
    const uintptr_t copy_args[] = {address_arg(output)};
    char copied[128]{};
    const auto copy_resume = game_base + 0x48b5e9 - image_base;
    auto* copy_format = &at<char>(0x5c2da4);
    memcpy(copy_format, "%s", sizeof("%s"));
    if (!begin_sprintf(copy_format, copied, copy_resume, copy_args)) return 28;
    if (finish_sprintf(fixture_formatter(copied, "%s", output)) != copy_resume ||
        !localize(copied, result) || result.find(L"7-21 物理 伤害。") == std::wstring::npos) return 29;
    char fatigue[96]{}, recovery[96]{}, weight[96]{};
    format(fatigue, fixture_text(0x5ce9a8,0x5ce9a8), 1);
    format(recovery, fixture_text(0x5ce9b8,0x5ce9b8), 10);
    format(weight, fixture_text(0x5c7eb8,0x5c7eb8), 4);
    auto* combine = &at<char>(0x5ce9d0);
    memcpy(combine, "%s%s", sizeof("%s%s"));
    auto* combine_weight = &at<char>(0x5c7f04);
    memcpy(combine_weight, "%s %s", sizeof("%s %s"));
    if (!scoped_format(0x4030f4, combine, address_arg(fatigue), address_arg(recovery), 0,
                       L"疲劳：1。 恢复所需回合：10。") ||
        !scoped_format(0x449292, combine_weight, address_arg(""), address_arg(weight), 0,
                       L"重量：4 磅。")) return 30;
    if (!scoped_format(0x403579, fixture_text(0x5cea54,0x5cea54), address_arg("~001~"), address_arg("5"),
                       address_arg(""), L"，持续 5 回合。")) return 31;
    char warning[96]{};
    format(warning, fixture_text(0x5c79a8,0x5c79a8));
    if (!scoped_format(0x48b5e9, copy_format, address_arg(warning),0,0,L"无法使用此技能。")) return 32;
    for (const auto buffer : {0x6add80u, 0x6ac2e0u, 0x6ac2e0u + 59 * 0x50}) {
        if (!localize(fixture_text(0x5c91fc, buffer), result) ||
            result != L"快速存档：完成。（按 F4 读取快速存档。）") return 33;
    }
    auto* binding = &at<char>(0x5cda44);
    memcpy(binding, "%s - %s", sizeof("%s - %s"));
    const auto key_row = [&](uintptr_t action, const char* key, const wchar_t* expected) {
        return scoped_format(0x4293e2, binding, address_arg(fixture_text(action, action)),
                             address_arg(key), 0, expected);
    };
    char no_shortcut[96]{};
    format(no_shortcut, fixture_text(0x5cda38, 0x5cda38));
    if (!key_row(0x5ecd54, "Shift+/", L"训练角色/查看属性 - Shift+/") ||
        !key_row(0x5ecdcc, no_shortcut, L"日志 - 无快捷键") ||
        !key_row(0x5ecfca, "F3", L"快速保存 - F3") ||
        !key_row(0x5ed006, "Space", L"等待 - 空格") ||
        !key_row(0x5ed402, "t", L"显示/隐藏文本控制台 - t")) return 34;
    if (!scoped_format(0x429409, fixture_text(0x5cda4c, 0x5cda4c),
                       address_arg(fixture_text(0x5ed16e, 0x5ed16e)), 0, 0,
                       L"选择按键 C - 输入快捷键")) return 35;
    int translated_actions = 0;
    for (uintptr_t action = 0x5ecd18; action <= 0x5ed402; action += 0x1e) {
        const auto entry = native_strings.find(action - image_base);
        if (entry == native_strings.end()) continue;
        const auto label = avzh::utf8(entry->second.target);
        if (!key_row(action, "a", (label + L" - a").c_str())) return 36;
        ++translated_actions;
    }
    if (translated_actions != 50) return 37;
    native_strings.clear();
    resource_strings.clear();
    constexpr char template_text[] = "Welcome %s (%d)";
    constexpr char literal[] = "Hard";
    game_base = reinterpret_cast<uintptr_t>(template_text) & ~uintptr_t(0xfffff);
    Entry translated{template_text, "欢迎%s（%d）", std::make_unique<avzh::Dictionary>()};
    translated.format->add(translated.source, translated.target);
    translated.format->prepare();
    native_strings.emplace(reinterpret_cast<uintptr_t>(template_text) - game_base, std::move(translated));
    native_strings.emplace(reinterpret_cast<uintptr_t>(literal) - game_base, Entry{literal, "困难", nullptr});
    resource_strings.emplace(1, "测试角色");
    if (format(output, template_text, "~001~", 3) != 17 || strcmp(output, "Welcome ~001~ (3)")) return 3;
    if (!localize(output, result) || result != L"欢迎测试角色（3）" || format_depth) return 4;
    if (format(output, literal) != 4 || strcmp(output, literal) || !localize(output, result) || result != L"困难") return 5;
    const std::string other_literal("Hard");
    if (format(output, other_literal.c_str()) != 4 || localize(output, result)) return 6;
    const wchar_t image[] = L"#Text Files (*.TXT)\0*.txt\0All Files (*.*)\0*.*\0";
    const wchar_t expected_label[] = L"Text Files (*.TXT)";
    auto* page = static_cast<char*>(VirtualAlloc(nullptr, sizeof(image), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!page) return 7;
    memcpy(page, image, sizeof(image));
    wide_slots = {{2, std::string(reinterpret_cast<const char*>(expected_label), sizeof(expected_label) - 2),
                   L"文本文件 (*.TXT)"}};
    wide_slots[0].replacement.resize(wide_slots[0].expected.size() / 2, L' ');
    DWORD previous = 0;
    if (!VirtualProtect(page, sizeof(image), PAGE_READONLY, &previous)) return 9;
    apply_wide_slots(page, sizeof(image));
    const auto suffix = 2 + wide_slots[0].expected.size();
    MEMORY_BASIC_INFORMATION region{};
    const bool verified = !memcmp(page + 2, wide_slots[0].replacement.data(), wide_slots[0].expected.size()) &&
        !memcmp(page + suffix, reinterpret_cast<const char*>(image) + suffix, sizeof(image) - suffix) &&
        VirtualQuery(page, &region, sizeof(region)) && region.Protect == PAGE_READONLY;
    VirtualFree(page, 0, MEM_RELEASE);
    if (!verified) return 10;
    if (avzh::FontSettings{100,true}.step(12) != 13 ||
        avzh::FontSettings{150,true}.step(12) != 19 || avzh::FontSettings{200,false}.step(12) != 25) return 11;
    movement_percent = 150;
    if (scaled_speed(65) != 98 || scaled_speed(0) != 0 || scaled_speed(-1) != -1 ||
        scaled_speed(30000) != 32767) return 12;
    avzh::CameraFollow follow;
    avzh::CameraFrame frame;
    frame.allowed = true;
    frame.mode = 10;
    frame.actors[0] = {true, 100, 100, 1};
    frame.actors[1] = {true, 200, 200, 1};
    if (follow.update(frame).follow) return 13;
    frame.actors[0].x += 20;
    frame.actors[1].x += 10;
    if (follow.update(frame).actor != 0) return 14;
    frame.actors[0].motion = 0;
    frame.actors[1].x += 10;
    if (follow.update(frame).follow) return 15;
    frame.actors[0].valid = false;
    frame.actors[1].x += 10;
    if (follow.update(frame).actor != 1) return 16;
    frame.mode = 15;
    frame.preferred = 0;
    if (follow.update(frame).follow) return 17;
    frame.preferred = 1;
    if (follow.update(frame).follow) return 18;
    frame.actors[1].x += 10;
    if (follow.update(frame).actor != 1) return 19;
    if (screen_point(123, -45) != 0x007bffd3) return 20;
    return 0;
}
#endif
