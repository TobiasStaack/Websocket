#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
#include <Windows.h>
#endif

#include <csignal>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef WEBSOCKET_EXAMPLE_C_API
#ifndef WEBSOCKET_C_API
#define WEBSOCKET_C_API
#endif
#include <websocket/api/websocket_c_api.h>
#else
#ifndef WEBSOCKET_CPP_API
#define WEBSOCKET_CPP_API
#endif
#include <websocket/api/websocket_cpp_api.h>
#endif

static ws_settings_t settings;

#ifdef WEBSOCKET_EXAMPLE_C_API
static void* ctx = nullptr;
#else
static c_websocket ws;
#endif

static void
handle_exit()
{
#ifdef WEBSOCKET_EXAMPLE_C_API
	websocket_close(ctx);

	while (websocket_operate(ctx))
	{
		// keep operating till all fd's have been terminated
	}

	websocket_destroy(ctx);
#else
	ws.close();

	while (ws.operate())
	{
		// keep operating till all fd's have been terminated
	}
#endif

	ws_settings_destroy(&settings);
}

#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
BOOL WINAPI
win_console_handler(const DWORD eventType)
{
	switch (eventType)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		handle_exit();
		return TRUE;

	default:
		return FALSE;
	}
}
#endif

void
exit_handler(const int signal_num)
{
	handle_exit();
	std::exit(signal_num);
}

#ifdef WEBSOCKET_EXAMPLE_C_API
void
websocket_on_open(void* ctx, const int fd, const char* addr)
{
	printf("new connection `%i;%s`\n", fd, addr);

	const char* const payload = "hello world!";

	void* frame = websocket_frame_create(opcode_text);
	websocket_frame_push(frame, reinterpret_cast<const unsigned char*>(payload), std::strlen(payload));
	websocket_frame_emit(ctx, fd, frame);
	websocket_frame_destroy(frame);
}

void
websocket_on_close(void* ctx, const int fd, const e_ws_closure_status status)
{
	printf("connection dropped `%i` with status `%i`\n", fd, status);
}

void
websocket_on_frame(void* ctx, const int fd, const e_ws_frame_opcode opcode, const unsigned char* payload, const size_t size)
{
	printf("income frame `%i` :: opcode -> %d\n\t%.*s\n", fd, opcode, static_cast<int>(size), reinterpret_cast<const char*>(payload));
}

void
websocket_on_error(void* ctx, const char* message)
{
	printf("%s\n", message);
}
#else
void
websocket_on_open(void* ctx, const int fd, const char* addr)
{
	printf("new connection `%i;%s`\n", fd, addr);

	const auto* ws = static_cast<c_websocket*>(ctx);

	const char* const payload = "hello world!";

	c_ws_frame frame(opcode_text);
	frame.push(reinterpret_cast<const unsigned char*>(payload), std::strlen(payload));
	ws->emit(fd, &frame);
}

void
websocket_on_close(void* ctx, const int fd, const e_ws_closure_status status)
{
	printf("connection dropped `%i` with status `%i`\n", fd, status);
}

void
websocket_on_frame(void* ctx, const int fd, const e_ws_frame_opcode opcode, const unsigned char* payload, const size_t size)
{
	printf("income frame `%i` :: opcode -> %d\n\t%.*s\n", fd, opcode, static_cast<int>(size), reinterpret_cast<const char*>(payload));
}

void
websocket_on_error(void* ctx, const char* message)
{
	printf("error: %s\n", message);
}
#endif

int
main()
{
#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
	if (!SetConsoleCtrlHandler(win_console_handler, TRUE))
	{
		return 1;
	}
#endif

	std::signal(SIGINT, exit_handler);

	ws_settings_init(&settings);

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
	settings.endpoint = endpoint_server;
	settings.auto_mask_frame = false;
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
	settings.endpoint = endpoint_client;
	settings.auto_mask_frame = true;
#endif

	settings.host = strdup("localhost:4433");

	settings.extensions.permessage_deflate.enabled = true;

#ifdef WEBSOCKET_EXAMPLE_C_API
	ctx = websocket_create();

	if (ctx == nullptr)
	{
		return 1;
	}

	if (websocket_on(ctx, WS_EVENT_OPEN, reinterpret_cast<void*>(websocket_on_open)) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}

	if (websocket_on(ctx, WS_EVENT_CLOSE, reinterpret_cast<void*>(websocket_on_close)) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}

	if (websocket_on(ctx, WS_EVENT_FRAME, reinterpret_cast<void*>(websocket_on_frame)) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}

	if (websocket_on(ctx, WS_EVENT_ERROR, reinterpret_cast<void*>(websocket_on_error)) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}

	if (websocket_setup(ctx, &settings) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
	if (websocket_bind(ctx, "localhost", "4433", nullptr) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
	if (websocket_open(ctx, "localhost", "4433", nullptr) == status_error)
	{
		websocket_destroy(ctx);
		ws_settings_destroy(&settings);
		return 1;
	}
#endif

	printf("websocket launched\n");

	while (websocket_operate(ctx))
	{
		// main loop
	}

	websocket_destroy(ctx);
#else
	if (ws.on(WS_EVENT_OPEN, reinterpret_cast<void*>(websocket_on_open)) == status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}

	if (ws.on(WS_EVENT_CLOSE, reinterpret_cast<void*>(websocket_on_close)) == status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}

	if (ws.on(WS_EVENT_FRAME, reinterpret_cast<void*>(websocket_on_frame)) == status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}

	if (ws.on(WS_EVENT_ERROR, reinterpret_cast<void*>(websocket_on_error)) == status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}

	if (ws.setup(&settings) != 0)
	{
		ws_settings_destroy(&settings);
		return 1;
	}

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
	if (ws.bind("localhost", "4433", nullptr) == e_ws_status::status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
	if (ws.open("localhost", "4433", nullptr) == e_ws_status::status_error)
	{
		ws_settings_destroy(&settings);
		return 1;
	}
#endif

	printf("websocket launched\n");

	while (ws.operate())
	{
		// main loop
	}
#endif

	ws_settings_destroy(&settings);

	return 0;
}
