/**
*                       Copyright (C) 2008-2015 HPDCS Group
*                       http://www.dis.uniroma1.it/~hpdcs
*
*
* This file is part of the Hijacker static binary instrumentation tool.
*
* Hijacker is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* Hijacker is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* hijacker; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
* @file graph.c
* @brief Graph functions
* @author Simone Economo
*/

#include <utils.h>
#include <prints.h>
#include <structs/structs.h>


/**
 * Inserts a new payload in the graph.
 *
 * @param graph Pointer to the graph.
 * @param elem Pointer to the payload.
 * @param label Annotation assigned to the newly-inserted node.
 *
 * @return Pointer to the newly-inserted node.
 */
graph_node_t *graph_insert(graph_t *graph, void *elem, unsigned long label) {
  unsigned int id;

  graph_node_t *node;

  if (!graph || !elem) {
    hinternal();
  }

  node = hcalloc(sizeof(graph_node_t));
  node->label = label;
  node->elem = elem;
  node->id = ++id;

  // Append the newly-created object to the list of nodes
  list_push_last(&gr->nodes, node);

  gr->numnodes += 1;

  return node;
}

/**
 * Connects two nodes in the graph.
 *
 * @param graph Pointer to the graph.
 * @param from Pointer to the source node.
 * @param to Pointer to the destination node.
 * @param label Annotation assigned to the newly-inserted edge.
 *
 * @return Pointer to the newly-inserted edge.
 */
graph_edge_t *graph_connect(graph_t *graph, graph_node_t *from,
                            graph_node_t *to, unsigned long label) {
  graph_edge_t *edge;

  if (!from || !to || from == to) {
    hinternal();
  }

  edge = hcalloc(sizeof(graph_edge_t));
  edge->label = label;
  edge->from = from;
  edge->to = to;

  // Connect source to destination
  list_push_last(&from->out, edge);

  // Connect destination to source
  list_push_last(&to->in, edge);

  // Append the newly-created object to the list of edges
  list_push_last(&gr->edges, edge);

  gr->numedges += 1;

  return edge;
}


__blind__ void *graph_remove(graph_t *graph, graph_node_t *node) {
  void *elem;
  graph_edge_t *outgoing_edge, *incoming_edge;

  if (!graph || !node) {
    hinternal();
  }

  elem = node->elem;

  // Remove outgoing edges
  list_for_each(&(node->out), outgoing_edge) {

    // Remove mirror edges in destinations
    list_for_each(&(edge->to.in), incoming_edge) {
      list_remove(&(edge->to.in), incoming_edge);
    }

    list_remove(&(node->out), outgoing_edge);
    graph->numedges -= 1;
  }

  // Remove incoming edges
  list_for_each(&(node->in), incoming_edge) {

    // Remove mirror edges in sources
    list_for_each(&(edge->from.out), outgoing_edge) {
      list_remove(&(edge->from.out), outgoing_edge);
    }

    list_remove(&(node->in), incoming_edge);
    graph->numedges -= 1;
  }

  graph->numnodes -= 1;
  free(node);

  return elem;
}


__blind__ void graph_disconnect(graph_t *graph, graph_node_t *from, graph_node_t *to) {
  graph_edge_t *edge;
  size_t count_outgoing, count_incoming;

  if (!from || !to || from == to) {
    hinternal();
  }

  // We iterate over all forward and backward edges because
  // we check for multiple insertions

  count_outgoing = count_incoming = 0;

  list_for_each(&(from->out), edge) {
    if (edge->to == to) {
      list_remove(&(from->out), edge);
      count_outgoing += 1;
    }
  }

  list_for_each(&(to->in), edge) {
    if (edge->from == from) {
      list_remove(&(to->in), edge);
      count_incoming += 1;
    }
  }

  if (count_outgoing != count_incoming) {
    hinternal();
  }

  graph->numedges -= count_outgoing;
}


/**
 * Performs the next visit to the graph. More specifically, it invokes
 * all visit functions provided by the kernel, at the appropriate
 * points. Then, it schedules visits to the current node's neighbors.
 * If the current node is empty or the pre-visit function returns `false`,
 * no further visits are scheduled from the currently-visited graph node.
 *
 * @param edge Pointer to the currently-visited edge.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
static void graph_visit_next(graph_edge_t *edge, graph_visit_kernel *kernel) {
  graph_node_t *node;
  list_node_t *tosched;

  // Base case: we've reached the end of a graph path
  if (node->visited == true) {
    return;
  }

  // Establishes which is the next node to schedule for a visit
  if (kernel->dir == GRAPH_DIR_FORWARD) {
    node = edge->to;
    tosched = node->in.first;
  }
  else if (kernel->dir == GRAPH_DIR_BACKWARD) {
    node = edge->from;
    tosched = node->out.first;
  }

  // Invoke the custom pre-visit function to the currently-visited
  // graph node
  if (kernel->pre_func) {
    if (kernel->pre_func(edge, kernel->payload) == false) {
      return;
    }
  }

  // The node is marked as visited and inserted into a list of
  // already-visited nodes
  node->visited = true;

  list_push_last(&kernel->visited, node);

  // A number of visits is invoked which is equal to the fanout
  // of the currently-visited node
  for (; tosched; tosched = tosched->next) {
    list_push_last(&kernel->scheduled, tosched->elem);

    if (kernel->policy == GRAPH_DEPTH_FIRST) {
      edge = list_pop_last(&kernel->scheduled);
    }
    else if (kernel->policy == GRAPH_BREADTH_FIRST) {
      edge = list_pop_first(&kernel->scheduled);
    }

    graph_visit_next(edge, kernel);
  }

  // Invoke the custom post-visit function to the currently-visited
  // graph node
  if (kernel->post_func) {
    kernel->post_func(edge, kernel->payload);
  }
}


/**
 * Performs a complete traversal of the graph. Depending on the provided
 * kernel, it can perform either a depth-first visit, or a bread-
 * first visit. In the first case, two sub-modes of traversal are
 * supported: pre-order and post-order. In the second case,
 * only pre-order is supported (also called level-order for bread-
 * first traversal).
 *
 * Observe that the duration of a traversal depends on both the size
 * of the graph, and the return value of the pre-order visit function
 * If it returns `false`, the traversal won't schedule any further visits
 * to the current node's children.
 *
 * @param edge Pointer to the starting edge from which traversal begins.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
void graph_visit(graph_t *graph, graph_visit_kernel *kernel) {
  list_t *scheduled, *visited;
  graph_node_t *node;

  if (!graph || !kernel) {
    hinternal();
  }
  // else if (kernel->policy != GRAPH_BREADTH_FIRST && kernel->policy != GRAPH_DEPTH_FIRST) {
  //  hinternal();
  // }
  // else if (kernel->dir != GRAPH_DIR_FORWARD && kernel->dir != GRAPH_DIR_BACKWARD) {
  //  hinternal();
  // }
  else if (!kernel->pre_func && !kernel->post_func) {
    hinternal();
  }

  // Visit initialization
  list_init(&kernel->scheduled);
  list_init(&kernel->visited);

  // TODO: Must be completed
  if (kernel->dir == GRAPH_DIR_FORWARD) {
    list_for_each(&(graph->sources), edge) {

    }
  }

  else if (kernel->dir == GRAPH_DIR_BACKWARD) {
    list_for_each(&(graph->sinks), edge) {

    }
  }

  // Starting the visit
  graph_visit_next(edge, kernel);

  // Clearing the effect of this visit not to hamper future ones
  while (!list_is_empty(&kernel->visited)) {
    node = list_pop_last(&kernel->visited);

    node->visited = false;
  }
}
