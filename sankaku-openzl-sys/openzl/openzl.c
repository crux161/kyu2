#include "openzl.h"

#include <stdlib.h>
#include <string.h>

struct openzl_context {
    uint8_t* serialized_graph;
    size_t serialized_graph_len;
};

static int copy_graph(openzl_context_t* context, openzl_graph_view_t serialized_graph) {
    if (context == NULL) {
        return OPENZL_INVALID_INPUT;
    }
    if (serialized_graph.len > 0 && serialized_graph.data == NULL) {
        return OPENZL_INVALID_INPUT;
    }

    uint8_t* next_graph = NULL;
    if (serialized_graph.len > 0) {
        next_graph = (uint8_t*)malloc(serialized_graph.len);
        if (next_graph == NULL) {
            return OPENZL_ALLOCATION_FAILED;
        }
        memcpy(next_graph, serialized_graph.data, serialized_graph.len);
    }

    if (context->serialized_graph != NULL) {
        free(context->serialized_graph);
    }
    context->serialized_graph = next_graph;
    context->serialized_graph_len = serialized_graph.len;
    return OPENZL_OK;
}

openzl_context_t* openzl_context_create(openzl_graph_view_t serialized_graph) {
    openzl_context_t* context = (openzl_context_t*)calloc(1, sizeof(openzl_context_t));
    if (context == NULL) {
        return NULL;
    }
    if (copy_graph(context, serialized_graph) != OPENZL_OK) {
        free(context);
        return NULL;
    }
    return context;
}

int openzl_context_update_graph(
    openzl_context_t* context,
    openzl_graph_view_t serialized_graph
) {
    return copy_graph(context, serialized_graph);
}

void openzl_context_destroy(openzl_context_t* context) {
    if (context == NULL) {
        return;
    }
    if (context->serialized_graph != NULL) {
        free(context->serialized_graph);
        context->serialized_graph = NULL;
        context->serialized_graph_len = 0;
    }
    free(context);
}

static int passthrough_process(
    const openzl_context_t* context,
    openzl_sao_input_view_t input,
    openzl_sao_output_view_t output,
    size_t* output_len
) {
    if (context == NULL || output_len == NULL || output.data == NULL) {
        return OPENZL_INVALID_INPUT;
    }
    if (input.len > 0 && input.data == NULL) {
        return OPENZL_INVALID_INPUT;
    }
    if (output.len < input.len) {
        return OPENZL_OUTPUT_TOO_SMALL;
    }

    if (input.len > 0) {
        memcpy(output.data, input.data, input.len);
    }
    *output_len = input.len;
    return OPENZL_OK;
}

int openzl_encode_sao(
    const openzl_context_t* context,
    openzl_sao_input_view_t input,
    openzl_sao_output_view_t output,
    size_t* output_len
) {
    return passthrough_process(context, input, output, output_len);
}

int openzl_decode_sao(
    const openzl_context_t* context,
    openzl_sao_input_view_t input,
    openzl_sao_output_view_t output,
    size_t* output_len
) {
    return passthrough_process(context, input, output, output_len);
}
