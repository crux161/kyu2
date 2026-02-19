#ifndef SANKAKU_OPENZL_H
#define SANKAKU_OPENZL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENZL_OK 0
#define OPENZL_INVALID_INPUT -1
#define OPENZL_OUTPUT_TOO_SMALL -2
#define OPENZL_ALLOCATION_FAILED -3

typedef struct openzl_context openzl_context_t;

typedef struct openzl_graph_view {
    const uint8_t* data;
    size_t len;
} openzl_graph_view_t;

typedef struct openzl_sao_input_view {
    const uint8_t* data;
    size_t len;
} openzl_sao_input_view_t;

typedef struct openzl_sao_output_view {
    uint8_t* data;
    size_t len;
} openzl_sao_output_view_t;

openzl_context_t* openzl_context_create(openzl_graph_view_t serialized_graph);
int openzl_context_update_graph(
    openzl_context_t* context,
    openzl_graph_view_t serialized_graph
);
void openzl_context_destroy(openzl_context_t* context);

int openzl_encode_sao(
    const openzl_context_t* context,
    openzl_sao_input_view_t input,
    openzl_sao_output_view_t output,
    size_t* output_len
);

int openzl_decode_sao(
    const openzl_context_t* context,
    openzl_sao_input_view_t input,
    openzl_sao_output_view_t output,
    size_t* output_len
);

#ifdef __cplusplus
}
#endif

#endif
