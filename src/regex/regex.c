/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file src/regex/regex.c
 * @brief library to create automatons from regular expressions
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_regex_lib.h"
#include "regex.h"

#define INITIAL_BITS 10

/**
 * Context that contains an id counter for states and transitions as well as a
 * DLL of automatons used as a stack for NFA construction.
 */
struct GNUNET_REGEX_Context
{
  /**
   * Unique state id.
   */
  unsigned int state_id;

  /**
   * Unique transition id.
   */
  unsigned int transition_id;

  /**
   * DLL of GNUNET_REGEX_Automaton's used as a stack.
   */
  struct GNUNET_REGEX_Automaton *stack_head;

  /**
   * DLL of GNUNET_REGEX_Automaton's used as a stack.
   */
  struct GNUNET_REGEX_Automaton *stack_tail;
};

/**
 * Type of an automaton.
 */
enum GNUNET_REGEX_AutomatonType
{
  NFA,
  DFA
};

/**
 * Automaton representation.
 */
struct GNUNET_REGEX_Automaton
{
  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct GNUNET_REGEX_Automaton *prev;

  /**
   * Linked list of NFAs used for partial NFA creation.
   */
  struct GNUNET_REGEX_Automaton *next;

  /**
   * First state of the automaton. This is mainly used for constructing an NFA,
   * where each NFA itself consists of one or more NFAs linked together.
   */
  struct GNUNET_REGEX_State *start;

  /**
   * End state of the partial NFA. This is undefined for DFAs
   */
  struct GNUNET_REGEX_State *end;

  /**
   * Number of states in the automaton.
   */
  unsigned int state_count;

  /**
   * DLL of states.
   */
  struct GNUNET_REGEX_State *states_head;

  /**
   * DLL of states
   */
  struct GNUNET_REGEX_State *states_tail;

  /**
   * Type of the automaton.
   */
  enum GNUNET_REGEX_AutomatonType type;

  /**
   * Regex
   */
  char *regex;

  /**
   * Computed regex (result of RX->NFA->DFA->RX)
   */
  char *computed_regex;
};

/**
 * A state. Can be used in DFA and NFA automatons.
 */
struct GNUNET_REGEX_State
{
  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_State *prev;

  /**
   * This is a linked list.
   */
  struct GNUNET_REGEX_State *next;

  /**
   * Unique state id.
   */
  unsigned int id;

  /**
   * If this is an accepting state or not.
   */
  int accepting;

  /**
   * Marking of the state. This is used for marking all visited states when
   * traversing all states of an automaton and for cases where the state id
   * cannot be used (dfa minimization).
   */
  int marked;

  /**
   * Marking the state as contained. This is used for checking, if the state is
   * contained in a set in constant time
   */
  int contained;

  /**
   * Marking the state as part of an SCC (Strongly Connected Component).  All
   * states with the same scc_id are part of the same SCC. scc_id is 0, if state
   * is not a part of any SCC.
   */
  unsigned int scc_id;

  /**
   * Used for SCC detection.
   */
  int index;

  /**
   * Used for SCC detection.
   */
  int lowlink;

  /**
   * Human readable name of the automaton. Used for debugging and graph
   * creation.
   */
  char *name;

  /**
   * Hash of the state.
   */
  struct GNUNET_HashCode hash;

  /**
   * State ID for proof creation.
   */
  unsigned int proof_id;

  /**
   * Proof for this state.
   */
  char *proof;

  /**
   * Number of transitions from this state to other states.
   */
  unsigned int transition_count;

  /**
   * DLL of transitions.
   */
  struct Transition *transitions_head;

  /**
   * DLL of transitions.
   */
  struct Transition *transitions_tail;

  /**
   * Set of states on which this state is based on. Used when creating a DFA out
   * of several NFA states.
   */
  struct GNUNET_REGEX_StateSet *nfa_set;
};

/**
 * Transition between two states. Each state can have 0-n transitions.  If label
 * is 0, this is considered to be an epsilon transition.
 */
struct Transition
{
  /**
   * This is a linked list.
   */
  struct Transition *prev;

  /**
   * This is a linked list.
   */
  struct Transition *next;

  /**
   * Unique id of this transition.
   */
  unsigned int id;

  /**
   * Label for this transition. This is basically the edge label for the graph.
   */
  char label;

  /**
   * State to which this transition leads.
   */
  struct GNUNET_REGEX_State *to_state;

  /**
   * State from which this transition origins.
   */
  struct GNUNET_REGEX_State *from_state;

  /**
   * Mark this transition. For example when reversing the automaton.
   */
  int mark;
};

/**
 * Set of states.
 */
struct GNUNET_REGEX_StateSet
{
  /**
   * Array of states.
   */
  struct GNUNET_REGEX_State **states;

  /**
   * Length of the 'states' array.
   */
  unsigned int len;
};

/*
 * Debug helper functions
 */
void
debug_print_transitions (struct GNUNET_REGEX_State *);

void
debug_print_state (struct GNUNET_REGEX_State *s)
{
  char *proof;

  if (NULL == s->proof)
    proof = "NULL";
  else
    proof = s->proof;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State %i: %s marked: %i accepting: %i scc_id: %i transitions: %i proof: %s\n",
              s->id, s->name, s->marked, s->accepting, s->scc_id,
              s->transition_count, proof);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transitions:\n");
  debug_print_transitions (s);
}

void
debug_print_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    debug_print_state (s);
}

void
debug_print_transition (struct Transition *t)
{
  char *to_state;
  char *from_state;
  char label;

  if (NULL == t)
    return;

  if (0 == t->label)
    label = '0';
  else
    label = t->label;

  if (NULL == t->to_state)
    to_state = "NULL";
  else
    to_state = t->to_state->name;

  if (NULL == t->from_state)
    from_state = "NULL";
  else
    from_state = t->from_state->name;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transition %i: From %s on %c to %s\n",
              t->id, from_state, label, to_state);
}

void
debug_print_transitions (struct GNUNET_REGEX_State *s)
{
  struct Transition *t;

  for (t = s->transitions_head; NULL != t; t = t->next)
    debug_print_transition (t);
}

/**
 * Recursive function doing DFS with 'v' as a start, detecting all SCCs inside
 * the subgraph reachable from 'v'. Used with scc_tarjan function to detect all
 * SCCs inside an automaton.
 *
 * @param ctx context
 * @param v start vertex
 * @param index current index
 * @param stack stack for saving all SCCs
 * @param stack_size current size of the stack
 */
static void
scc_tarjan_strongconnect (unsigned int *scc_counter,
                          struct GNUNET_REGEX_State *v, unsigned int *index,
                          struct GNUNET_REGEX_State **stack,
                          unsigned int *stack_size)
{
  struct GNUNET_REGEX_State *w;
  struct Transition *t;

  v->index = *index;
  v->lowlink = *index;
  (*index)++;
  stack[(*stack_size)++] = v;
  v->contained = 1;

  for (t = v->transitions_head; NULL != t; t = t->next)
  {
    w = t->to_state;
    if (NULL != w && w->index < 0)
    {
      scc_tarjan_strongconnect (scc_counter, w, index, stack, stack_size);
      v->lowlink = (v->lowlink > w->lowlink) ? w->lowlink : v->lowlink;
    }
    else if (0 != w->contained)
      v->lowlink = (v->lowlink > w->index) ? w->index : v->lowlink;
  }

  if (v->lowlink == v->index)
  {
    w = stack[--(*stack_size)];
    w->contained = 0;

    if (v != w)
    {
      (*scc_counter)++;
      while (v != w)
      {
        w->scc_id = *scc_counter;
        w = stack[--(*stack_size)];
        w->contained = 0;
      }
      w->scc_id = *scc_counter;
    }
  }
}

/**
 * Detect all SCCs (Strongly Connected Components) inside the given automaton.
 * SCCs will be marked using the scc_id on each state.
 *
 * @param ctx context
 * @param a automaton
 */
static void
scc_tarjan (struct GNUNET_REGEX_Automaton *a)
{
  unsigned int index;
  unsigned int scc_counter;
  struct GNUNET_REGEX_State *v;
  struct GNUNET_REGEX_State *stack[a->state_count];
  unsigned int stack_size;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    v->contained = 0;
    v->index = -1;
    v->lowlink = -1;
  }

  stack_size = 0;
  index = 0;
  scc_counter = 0;

  for (v = a->states_head; NULL != v; v = v->next)
  {
    if (v->index < 0)
      scc_tarjan_strongconnect (&scc_counter, v, &index, stack, &stack_size);
  }
}

/**
 * Adds a transition from one state to another on 'label'. Does not add
 * duplicate states.
 *
 * @param ctx context
 * @param from_state starting state for the transition
 * @param label transition label
 * @param to_state state to where the transition should point to
 */
static void
state_add_transition (struct GNUNET_REGEX_Context *ctx,
                      struct GNUNET_REGEX_State *from_state, const char label,
                      struct GNUNET_REGEX_State *to_state)
{
  int is_dup;
  struct Transition *t;
  struct Transition *oth;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  // Do not add duplicate state transitions
  is_dup = GNUNET_NO;
  for (t = from_state->transitions_head; NULL != t; t = t->next)
  {
    if (t->to_state == to_state && t->label == label &&
        t->from_state == from_state)
    {
      is_dup = GNUNET_YES;
      break;
    }
  }

  if (is_dup)
    return;

  // sort transitions by label
  for (oth = from_state->transitions_head; NULL != oth; oth = oth->next)
  {
    if (oth->label > label)
      break;
  }

  t = GNUNET_malloc (sizeof (struct Transition));
  t->id = ctx->transition_id++;
  t->label = label;
  t->to_state = to_state;
  t->from_state = from_state;

  // Add outgoing transition to 'from_state'
  from_state->transition_count++;
  GNUNET_CONTAINER_DLL_insert_before (from_state->transitions_head,
                                      from_state->transitions_tail, oth, t);
}

/**
 * Compare two states. Used for sorting.
 *
 * @param a first state
 * @param b second state
 *
 * @return an integer less than, equal to, or greater than zero
 *         if the first argument is considered to be respectively
 *         less than, equal to, or greater than the second.
 */
static int
state_compare (const void *a, const void *b)
{
  struct GNUNET_REGEX_State **s1;
  struct GNUNET_REGEX_State **s2;

  s1 = (struct GNUNET_REGEX_State **) a;
  s2 = (struct GNUNET_REGEX_State **) b;

  return (*s1)->id - (*s2)->id;
}

/**
 * Get all edges leaving state 's'.
 *
 * @param s state.
 * @param edges all edges leaving 's'.
 *
 * @return number of edges.
 */
static unsigned int
state_get_edges (struct GNUNET_REGEX_State *s, struct GNUNET_REGEX_Edge *edges)
{
  struct Transition *t;
  unsigned int count;

  if (NULL == s)
    return 0;

  count = 0;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != t->to_state)
    {
      edges[count].label = &t->label;
      edges[count].destination = t->to_state->hash;
      count++;
    }
  }
  return count;
}

/**
 * Compare to state sets by comparing the id's of the states that are contained
 * in each set. Both sets are expected to be sorted by id!
 *
 * @param sset1 first state set
 * @param sset2 second state set
 *
 * @return an integer less than, equal to, or greater than zero
 *         if the first argument is considered to be respectively
 *         less than, equal to, or greater than the second.
 */
static int
state_set_compare (struct GNUNET_REGEX_StateSet *sset1,
                   struct GNUNET_REGEX_StateSet *sset2)
{
  int result;
  int i;

  if (NULL == sset1 || NULL == sset2)
    return 1;

  result = sset1->len - sset2->len;

  for (i = 0; i < sset1->len; i++)
  {
    if (0 != result)
      break;

    result = state_compare (&sset1->states[i], &sset2->states[i]);
  }
  return result;
}

/**
 * Clears the given StateSet 'set'
 *
 * @param set set to be cleared
 */
static void
state_set_clear (struct GNUNET_REGEX_StateSet *set)
{
  if (NULL != set)
  {
    GNUNET_free_non_null (set->states);
    GNUNET_free (set);
  }
}

/**
 * Clears an automaton fragment. Does not destroy the states inside the
 * automaton.
 *
 * @param a automaton to be cleared
 */
static void
automaton_fragment_clear (struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return;

  a->start = NULL;
  a->end = NULL;
  a->states_head = NULL;
  a->states_tail = NULL;
  a->state_count = 0;
  GNUNET_free (a);
}

/**
 * Frees the memory used by State 's'
 *
 * @param s state that should be destroyed
 */
static void
automaton_destroy_state (struct GNUNET_REGEX_State *s)
{
  struct Transition *t;
  struct Transition *next_t;

  if (NULL == s)
    return;

  GNUNET_free_non_null (s->name);
  GNUNET_free_non_null (s->proof);

  for (t = s->transitions_head; NULL != t; t = next_t)
  {
    next_t = t->next;
    GNUNET_CONTAINER_DLL_remove (s->transitions_head, s->transitions_tail, t);
    GNUNET_free (t);
  }

  state_set_clear (s->nfa_set);

  GNUNET_free (s);
}

/**
 * Remove a state from the given automaton 'a'. Always use this function when
 * altering the states of an automaton. Will also remove all transitions leading
 * to this state, before destroying it.
 *
 * @param a automaton
 * @param s state to remove
 */
static void
automaton_remove_state (struct GNUNET_REGEX_Automaton *a,
                        struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_State *ss;
  struct GNUNET_REGEX_State *s_check;
  struct Transition *t_check;

  if (NULL == a || NULL == s)
    return;

  // remove state
  ss = s;
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
  a->state_count--;

  // remove all transitions leading to this state
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check->next)
    {
      if (t_check->to_state == ss)
      {
        GNUNET_CONTAINER_DLL_remove (s_check->transitions_head,
                                     s_check->transitions_tail, t_check);
        s_check->transition_count--;
      }
    }
  }

  automaton_destroy_state (ss);
}

/**
 * Merge two states into one. Will merge 's1' and 's2' into 's1' and destroy
 * 's2'.
 *
 * @param ctx context
 * @param a automaton
 * @param s1 first state
 * @param s2 second state, will be destroyed
 */
static void
automaton_merge_states (struct GNUNET_REGEX_Context *ctx,
                        struct GNUNET_REGEX_Automaton *a,
                        struct GNUNET_REGEX_State *s1,
                        struct GNUNET_REGEX_State *s2)
{
  struct GNUNET_REGEX_State *s_check;
  struct Transition *t_check;
  char *new_name;

  GNUNET_assert (NULL != ctx && NULL != a && NULL != s1 && NULL != s2);

  if (s1 == s2)
    return;

  // 1. Make all transitions pointing to s2 point to s1
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check->next)
    {
      if (s2 == t_check->to_state)
        t_check->to_state = s1;
    }
  }

  // 2. Add all transitions from s2 to sX to s1
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    if (t_check->to_state != s1)
      state_add_transition (ctx, s1, t_check->label, t_check->to_state);
  }

  // 3. Rename s1 to {s1,s2}
  new_name = s1->name;
  GNUNET_asprintf (&s1->name, "{%s,%s}", new_name, s2->name);
  GNUNET_free (new_name);

  // remove state
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s2);
  a->state_count--;
  automaton_destroy_state (s2);
}

/**
 * Add a state to the automaton 'a', always use this function to alter the
 * states DLL of the automaton.
 *
 * @param a automaton to add the state to
 * @param s state that should be added
 */
static void
automaton_add_state (struct GNUNET_REGEX_Automaton *a,
                     struct GNUNET_REGEX_State *s)
{
  GNUNET_CONTAINER_DLL_insert (a->states_head, a->states_tail, s);
  a->state_count++;
}

/**
 * Function that is called with each state, when traversing an automaton.
 *
 * @param cls closure.
 * @param count current count of the state, from 0 to a->state_count -1.
 * @param s state.
 */
typedef void (*GNUNET_REGEX_traverse_action) (void *cls, unsigned int count,
                                              struct GNUNET_REGEX_State * s);

/**
 * Depth-first traversal of all states that are reachable from state 's'. Expects the states to
 * be unmarked (s->marked == GNUNET_NO). Performs 'action' on each visited
 * state.
 *
 * @param s start state.
 * @param count current count of the state.
 * @param action action to be performed on each state.
 * @param action_cls closure for action
 */
static void
automaton_state_traverse (struct GNUNET_REGEX_State *s,
                          unsigned int *count,
                          GNUNET_REGEX_traverse_action action,
			  void *action_cls)
{
  struct Transition *t;

  if (GNUNET_NO != s->marked)
    return;
  s->marked = GNUNET_YES;
  if (NULL != action)
    action (action_cls, *count, s);
  (*count)++;
  for (t = s->transitions_head; NULL != t; t = t->next)
    automaton_state_traverse (t->to_state, count, action, action_cls);  
}


/**
 * Traverses the given automaton from it's start state, visiting all reachable
 * states and calling 'action' on each one of them.
 *
 * @param a automaton.
 * @param action action to be performed on each state.
 * @param action_cls closure for action
 */
static void
automaton_traverse (struct GNUNET_REGEX_Automaton *a,
                    GNUNET_REGEX_traverse_action action,
		    void *action_cls)
{
  unsigned int count;
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;
  count = 0;
  automaton_state_traverse (a->start, &count, action, action_cls);
}


/**
 * Check if the given string 'str' needs parentheses around it when
 * using it to generate a regex.
 *
 * Currently only tests for first and last characters being '()' respectively.
 * FIXME: What about "(ab)|(cd)"?  
 *
 * @param str string
 *
 * @return GNUNET_YES if parentheses are needed, GNUNET_NO otherwise
 */
static int
needs_parentheses (const char *str)
{
  size_t slen;
  const char *op;
  const char *cl;
  const char *pos;
  unsigned int cnt;

  if ( (NULL == str) ||
       ((slen = strlen(str)) < 2) )
    return GNUNET_NO;
  
  if ('(' != str[0])
    return GNUNET_YES;
  cnt = 1;
  pos = &str[1];
  while (cnt > 0)
  {
    cl = strchr (pos, ')');
    if (NULL == cl)
    {
      GNUNET_break (0);
      return GNUNET_YES;
    }
    op = strchr (pos, '(');
    if ( (NULL != op) && (op < cl))
    {
      cnt++;
      pos = op + 1;
      continue;
    }
    /* got ')' first */
    cnt--;
    pos = cl + 1;
  }
  return (*pos == '\0') ? GNUNET_NO : GNUNET_YES;
}


/**
 * Remove parentheses surrounding string 'str'.
 * Example: "(a)" becomes "a".
 * You need to GNUNET_free the returned string.
 *
 * Currently only tests for first and last characters being '()' respectively.
 * FIXME: What about "(ab)|(cd)"?  
 *
 * @param str string, free'd or re-used by this function, can be NULL
 *
 * @return string without surrounding parentheses, string 'str' if no preceding
 *         epsilon could be found, NULL if 'str' was NULL
 */
static char *
remove_parentheses (char *str)
{
  size_t slen;

  if ( (NULL == str) || ('(' != str[0]) || (str[(slen = strlen(str)) - 1] != ')') )
    return str;
  memmove (str, &str[1], slen - 2);
  str[slen - 2] = '\0';
  return str;
}


/**
 * Check if the string 'str' starts with an epsilon (empty string).
 * Example: "(|a)" is starting with an epsilon.
 *
 * @param str string to test
 *
 * @return 0 if str has no epsilon, 1 if str starts with '(|' and ends with ')'
 */
static int
has_epsilon (const char *str)
{
  return  (NULL != str) && ('(' == str[0]) && ('|' == str[1]) && (')' == str[strlen(str) - 1]);
}


/**
 * Remove an epsilon from the string str. Where epsilon is an empty string
 * Example: str = "(|a|b|c)", result: "a|b|c"
 * The returned string needs to be freed.
 *
 * @param str string
 *
 * @return string without preceding epsilon, string 'str' if no preceding epsilon
 *         could be found, NULL if 'str' was NULL
 */
static char *
remove_epsilon (const char *str)
{
  size_t len;

  if (NULL == str)
    return NULL;
  if ( ('(' == str[0]) && ('|' == str[1]) )
  {
    len = strlen (str);
    if (')' == str[len-1])    
      return GNUNET_strndup (&str[2], len - 3);
  }
  return GNUNET_strdup (str);
}

/** 
 * Compare 'str1', starting from position 'k',  with whole 'str2'
 * 
 * @param str1 first string to compare, starting from position 'k'
 * @param str2 second string for comparison
 * @param k starting position in 'str1'
 * 
 * @return -1 if any of the strings is NULL, 0 if equal, non 0 otherwise
 */
static int
strkcmp (const char *str1, const char *str2, size_t k)
{
  if ( (NULL == str1) || (NULL == str2) || (strlen(str1) < k) )
    return -1;
  return strcmp (&str1[k], str2);
}


/**
 * Compare two strings for equality. If either is NULL (or if both are
 * NULL), they are not equal.
 *
 * @return 0 if the strings are the same, 1 or -1 if not
 */
static int
nullstrcmp (const char *str1, const char *str2)
{
  if ( (NULL == str1) || (NULL == str2) )
    return -1;
  return strcmp (str1, str2);
}

/** 
 * Helper function used as 'action' in 'automaton_traverse' function to create
 * the depth-first numbering of the states.
 * 
 * @param cls states array.
 * @param count current state counter.
 * @param s current state.
 */
static void
number_states (void *cls, unsigned int count, struct GNUNET_REGEX_State *s)
{
  struct GNUNET_REGEX_State **states = cls;

  s->proof_id = count;
  states[count] = s;
}


/**
 * create proofs for all states in the given automaton. Implementation of the
 * algorithm descriped in chapter 3.2.1 of "Automata Theory, Languages, and
 * Computation 3rd Edition" by Hopcroft, Motwani and Ullman.
 *
 * @param a automaton.
 */
static void
automaton_create_proofs (struct GNUNET_REGEX_Automaton *a)
{
  unsigned int n = a->state_count;
  struct GNUNET_REGEX_State *states[n];
  char *R_last[n][n];
  char *R_cur[n][n];
  struct Transition *t;
  char *R_cur_l;
  char *R_cur_r;
  char *temp_a;
  char *temp_b;
  char *R_temp_ij;
  char *R_temp_ik;
  char *R_temp_kj;
  char *R_temp_kk;
  char *complete_regex;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  int cnt;
  int eps_check;
  int ij_ik_cmp;
  int ij_kj_cmp;
  int ik_kj_cmp;
  int ik_kk_cmp;
  int kk_kj_cmp;
  int clean_ik_kk_cmp;
  int clean_kk_kj_cmp;
  int length;
  int length_l;
  int length_r;

  /* create depth-first numbering of the states, initializes 'state' */
  automaton_traverse (a, &number_states, states);

  /* Compute regular expressions of length "1" between each pair of states */
  for (i = 0; i < n; i++)
  {
    for (j=0;j<n;j++)
    {
      R_cur[i][j] = NULL;
      R_last[i][j] = NULL;
    }
    for (t = states[i]->transitions_head; NULL != t; t = t->next)
    {
      j = t->to_state->proof_id;      
      if (NULL == R_last[i][j])
	GNUNET_asprintf (&R_last[i][j], "%c", t->label);
      else
	{
	  temp_a = R_last[i][j];
	  GNUNET_asprintf (&R_last[i][j], "%s|%c", R_last[i][j], t->label);
	  GNUNET_free (temp_a);
	}
      if (GNUNET_YES == needs_parentheses (R_last[i][j]))
        {
	  temp_a = R_last[i][j];
	  GNUNET_asprintf (&R_last[i][j], "(%s)", R_last[i][j]);
	  GNUNET_free (temp_a);
	}
    }
    if (NULL == R_last[i][i])
      GNUNET_asprintf (&R_last[i][i], "");
    else
      {
	temp_a = R_last[i][i];
	GNUNET_asprintf (&R_last[i][i], "(|%s)", R_last[i][i]);
	GNUNET_free (temp_a);
      }  
  }


  // INDUCTION
  for (k = 0; k < n; k++)
  {
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, */
        /* ">>> R_last[i][j] = %s R_last[i][k] = %s " */
        /* "R_last[k][k] = %s R_last[k][j] = %s\n", R_last[i][j], */
        /* R_last[i][k], R_last[k][k], R_last[k][j]); */

        R_cur[i][j] = NULL;
        R_cur_r = NULL;
        R_cur_l = NULL;

	// cache results from strcmp, we might need these many times
	ij_kj_cmp = nullstrcmp (R_last[i][j], R_last[k][j]);
	ij_ik_cmp = nullstrcmp (R_last[i][j], R_last[i][k]);
	ik_kk_cmp = nullstrcmp (R_last[i][k], R_last[k][k]);
	ik_kj_cmp = nullstrcmp (R_last[i][k], R_last[k][j]);
	kk_kj_cmp = nullstrcmp (R_last[k][k], R_last[k][j]);

        // $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk})^* R^{(k-1)}_{kj}
        // With: R_cur[i][j] = R_cur_l | R_cur_r
        // Rij(k) = Rij(k-1), because right side (R_cur_r) is empty set (NULL)
        if ((NULL == R_last[i][k] || NULL == R_last[k][j] ||
             NULL == R_last[k][k]) && NULL != R_last[i][j])
        {
          R_cur[i][j] = GNUNET_strdup (R_last[i][j]);
        }
        // Everything is NULL, so Rij(k) = NULL
        else if ((NULL == R_last[i][k] || NULL == R_last[k][j] ||
                  NULL == R_last[k][k]) && NULL == R_last[i][j])
        {
          R_cur[i][j] = NULL;
        }
        // Right side (R_cur_r) not NULL
        else
        {
          /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, */
          /* "R_temp_ij = %s  R_temp_ik = %s  R_temp_kk = %s  R_temp_kj = %s\n", */
          /* R_temp_ij, R_temp_ik, R_temp_kk, R_temp_kj); */

          // Assign R_temp_(ik|kk|kj) to R_last[][] and remove epsilon as well
          // as parentheses, so we can better compare the contents
	  R_temp_ik = remove_parentheses (remove_epsilon (R_last[i][k]));
          R_temp_kk = remove_parentheses (remove_epsilon (R_last[k][k]));
          R_temp_kj = remove_parentheses (remove_epsilon (R_last[k][j]));

          clean_ik_kk_cmp = nullstrcmp (R_last[i][k], R_temp_kk);
          clean_kk_kj_cmp = nullstrcmp (R_temp_kk, R_last[k][j]);
          
          // construct R_cur_l (and, if necessary R_cur_r)
          if (NULL != R_last[i][j])
          {
            // Assign R_temp_ij to R_last[i][j] and remove epsilon as well
            // as parentheses, so we can better compare the contents
	    R_temp_ij = remove_parentheses (remove_epsilon (R_last[i][j]));

            if (0 == strcmp (R_temp_ij, R_temp_ik) &&
                0 == strcmp (R_temp_ik, R_temp_kk) &&
                0 == strcmp (R_temp_kk, R_temp_kj))
            {
              if (0 == strlen (R_temp_ij))
              {
                R_cur_r = GNUNET_strdup ("");
              }
              // a|(e|a)a*(e|a) = a*
              // a|(e|a)(e|a)*(e|a) = a*
              // (e|a)|aa*a = a*
              // (e|a)|aa*(e|a) = a*
              // (e|a)|(e|a)a*a = a*
              // (e|a)|(e|a)a*(e|a) = a*
              // (e|a)|(e|a)(e|a)*(e|a) = a*
              else if ((0 == strncmp (R_last[i][j], "(|", 2)) ||
                       (0 == strncmp (R_last[i][k], "(|", 2) &&
                        0 == strncmp (R_last[k][j], "(|", 2)))
              {
                if (GNUNET_YES == needs_parentheses (R_temp_ij))
                  GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_ij);
                else
                  GNUNET_asprintf (&R_cur_r, "%s*", R_temp_ij);
              }
              // a|aa*a = a+
              // a|(e|a)a*a = a+
              // a|aa*(e|a) = a+
              // a|(e|a)(e|a)*a = a+
              // a|a(e|a)*(e|a) = a+
              else
              {
                if (GNUNET_YES == needs_parentheses (R_temp_ij))
                  GNUNET_asprintf (&R_cur_r, "(%s)+", R_temp_ij);
                else
                  GNUNET_asprintf (&R_cur_r, "%s+", R_temp_ij);
              }
            }
            // a|ab*b = ab*
            else if (0 == ij_ik_cmp && 0 == clean_kk_kj_cmp &&
                     0 != clean_ik_kk_cmp)
            {
              if (strlen (R_last[k][k]) < 1)
                R_cur_r = GNUNET_strdup (R_last[i][j]);
              else if (GNUNET_YES == needs_parentheses (R_temp_kk))
                GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last[i][j], R_temp_kk);
              else
                GNUNET_asprintf (&R_cur_r, "%s%s*", R_last[i][j], R_last[k][k]);

              R_cur_l = NULL;
            }
            // a|bb*a = b*a
            else if (0 == ij_kj_cmp && 0 == clean_ik_kk_cmp &&
                     0 != clean_kk_kj_cmp)
            {
              if (strlen (R_last[k][k]) < 1)
                R_cur_r = GNUNET_strdup (R_last[k][j]);
              else if (GNUNET_YES == needs_parentheses (R_temp_kk))
                GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk, R_last[k][j]);
              else
                GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last[k][j]);

              R_cur_l = NULL;
            }
            // a|a(e|b)*(e|b) = a|ab* = a|a|ab|abb|abbb|... = ab*
            else if (0 == ij_ik_cmp && 0 == kk_kj_cmp &&
                     !has_epsilon (R_last[i][j]) && has_epsilon (R_last[k][k]))
            {
              if (needs_parentheses (R_temp_kk))
                GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last[i][j], R_temp_kk);
              else
                GNUNET_asprintf (&R_cur_r, "%s%s*", R_last[i][j], R_temp_kk);

              R_cur_l = NULL;
            }
            // a|(e|b)(e|b)*a = a|b*a = a|a|ba|bba|bbba|...  = b*a
            else if (0 == ij_kj_cmp && 0 == ik_kk_cmp &&
                     !has_epsilon (R_last[i][j]) && has_epsilon (R_last[k][k]))
            {
              if (needs_parentheses (R_temp_kk))
                GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk, R_last[i][j]);
              else
                GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last[i][j]);

              R_cur_l = NULL;
            }
            else
            {
              /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "NO SIMPLIFICATION\n"); */
	      temp_a = (NULL == R_last[i][j]) ? NULL : GNUNET_strdup (R_last[i][j]);
              temp_a = remove_parentheses (temp_a);
              R_cur_l = temp_a;
            }

            GNUNET_free_non_null (R_temp_ij);
          }
          // we have no left side
          else
          {
            R_cur_l = NULL;
          }

          // construct R_cur_r, if not already constructed
          if (NULL == R_cur_r)
          {
            length = strlen (R_temp_kk) - strlen (R_last[i][k]);

            // a(ba)*bx = (ab)+x
            if (length > 0 && NULL != R_last[k][k] && 0 < strlen (R_last[k][k])
                && NULL != R_last[k][j] && 0 < strlen (R_last[k][j]) &&
                NULL != R_last[i][k] && 0 < strlen (R_last[i][k]) &&
                0 == strkcmp (R_temp_kk, R_last[i][k], length) &&
                0 == strncmp (R_temp_kk, R_last[k][j], length))
            {
              temp_a = GNUNET_malloc (length + 1);
              temp_b = GNUNET_malloc ((strlen (R_last[k][j]) - length) + 1);

              length_l = 0;
              length_r = 0;

              for (cnt = 0; cnt < strlen (R_last[k][j]); cnt++)
              {
                if (cnt < length)
                {
                  temp_a[length_l] = R_last[k][j][cnt];
                  length_l++;
                }
                else
                {
                  temp_b[length_r] = R_last[k][j][cnt];
                  length_r++;
                }
              }
              temp_a[length_l] = '\0';
              temp_b[length_r] = '\0';

              // e|(ab)+ = (ab)*
              if (NULL != R_cur_l && 0 == strlen (R_cur_l) &&
                  0 == strlen (temp_b))
              {
                GNUNET_asprintf (&R_cur_r, "(%s%s)*", R_last[i][k], temp_a);
                GNUNET_free (R_cur_l);
                R_cur_l = NULL;
              }
              else
              {
                GNUNET_asprintf (&R_cur_r, "(%s%s)+%s", R_last[i][k], temp_a,
                                 temp_b);
              }
              GNUNET_free (temp_a);
              GNUNET_free (temp_b);
            }
            else if (0 == strcmp (R_temp_ik, R_temp_kk) &&
                     0 == strcmp (R_temp_kk, R_temp_kj))
            {
              // (e|a)a*(e|a) = a*
              // (e|a)(e|a)*(e|a) = a*
              if (has_epsilon (R_last[i][k]) && has_epsilon (R_last[k][j]))
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "(%s)*", R_temp_kk);
                else
                  GNUNET_asprintf (&R_cur_r, "%s*", R_temp_kk);
              }
              // aa*a = a+a
              else if (0 == clean_ik_kk_cmp && 0 == clean_kk_kj_cmp &&
                       !has_epsilon (R_last[i][k]))
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
                else
                  GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk, R_temp_kk);
              }
              // (e|a)a*a = a+
              // aa*(e|a) = a+
              // a(e|a)*(e|a) = a+
              // (e|a)a*a = a+
              else
              {
                eps_check =
                    (has_epsilon (R_last[i][k]) + has_epsilon (R_last[k][k]) +
                     has_epsilon (R_last[k][j]));

                if (eps_check == 1)
                {
                  if (needs_parentheses (R_temp_kk))
                    GNUNET_asprintf (&R_cur_r, "(%s)+", R_temp_kk);
                  else
                    GNUNET_asprintf (&R_cur_r, "%s+", R_temp_kk);
                }
              }
            }
            // aa*b = a+b
            // (e|a)(e|a)*b = a*b
            else if (0 == strcmp (R_temp_ik, R_temp_kk))
            {
              if (has_epsilon (R_last[i][k]))
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "(%s)*%s", R_temp_kk,
                                   R_last[k][j]);
                else
                  GNUNET_asprintf (&R_cur_r, "%s*%s", R_temp_kk, R_last[k][j]);
              }
              else
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_temp_kk,
                                   R_last[k][j]);
                else
                  GNUNET_asprintf (&R_cur_r, "%s+%s", R_temp_kk, R_last[k][j]);
              }
            }
            // ba*a = ba+
            // b(e|a)*(e|a) = ba*
            else if (0 == strcmp (R_temp_kk, R_temp_kj))
            {
              if (has_epsilon (R_last[k][j]))
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "%s(%s)*", R_last[i][k],
                                   R_temp_kk);
                else
                  GNUNET_asprintf (&R_cur_r, "%s%s*", R_last[i][k], R_temp_kk);
              }
              else
              {
                if (needs_parentheses (R_temp_kk))
                  GNUNET_asprintf (&R_cur_r, "(%s)+%s", R_last[i][k],
                                   R_temp_kk);
                else
                  GNUNET_asprintf (&R_cur_r, "%s+%s", R_last[i][k], R_temp_kk);
              }
            }
            else
            {
              if (strlen (R_temp_kk) > 0)
              {
                if (needs_parentheses (R_temp_kk))
                {
                  GNUNET_asprintf (&R_cur_r, "%s(%s)*%s", R_last[i][k],
                                   R_temp_kk, R_last[k][j]);
                }
                else
                {
                  GNUNET_asprintf (&R_cur_r, "%s%s*%s", R_last[i][k], R_temp_kk,
                                   R_last[k][j]);
                }
              }
              else
              {
                GNUNET_asprintf (&R_cur_r, "%s%s", R_last[i][k], R_last[k][j]);
              }
            }
          }

          /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "R_cur_l: %s\n", R_cur_l); */
          /* GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "R_cur_r: %s\n", R_cur_r); */

          // putting it all together
          if (NULL != R_cur_l && NULL != R_cur_r)
          {
            // a|a = a
            if (0 == strcmp (R_cur_l, R_cur_r))
            {
              R_cur[i][j] = GNUNET_strdup (R_cur_l);
            }
            // R_cur_l | R_cur_r
            else
            {
              GNUNET_asprintf (&R_cur[i][j], "(%s|%s)", R_cur_l, R_cur_r);
            }
          }
          else if (NULL != R_cur_l)
          {
            R_cur[i][j] = GNUNET_strdup (R_cur_l);
          }
          else if (NULL != R_cur_r)
          {
            R_cur[i][j] = GNUNET_strdup (R_cur_r);
          }
          else
          {
            R_cur[i][j] = NULL;
          }

          GNUNET_free_non_null (R_cur_l);
          GNUNET_free_non_null (R_cur_r);

          GNUNET_free_non_null (R_temp_ik);
          GNUNET_free_non_null (R_temp_kk);
          GNUNET_free_non_null (R_temp_kj);
        }
      }
    }

    // set R_last = R_cur
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        GNUNET_free_non_null (R_last[i][j]);
	R_last[i][j] = R_cur[i][j];
	R_cur[i][j] = NULL;       
      }
    }
  }

  // assign proofs and hashes
  for (i = 0; i < n; i++)
  {
    if (NULL != R_last[a->start->proof_id][i])
    {
      states[i]->proof = GNUNET_strdup (R_last[a->start->proof_id][i]);
      GNUNET_CRYPTO_hash (states[i]->proof, strlen (states[i]->proof),
                          &states[i]->hash);
    }
  }

  // complete regex for whole DFA: union of all pairs (start state/accepting state(s)).
  complete_regex = NULL;
  for (i = 0; i < n; i++)
  {
    if (states[i]->accepting)
    {
      if (NULL == complete_regex && 0 < strlen (R_last[a->start->proof_id][i]))
        GNUNET_asprintf (&complete_regex, "%s", R_last[a->start->proof_id][i]);
      else if (NULL != R_last[a->start->proof_id][i] &&
               0 < strlen (R_last[a->start->proof_id][i]))
      {
        temp_a = complete_regex;
        GNUNET_asprintf (&complete_regex, "%s|%s", complete_regex,
                         R_last[a->start->proof_id][i]);
        GNUNET_free (temp_a);
      }
    }
  }
  a->computed_regex = complete_regex;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "---------------------------------------------\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Regex: %s\n", a->regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Complete Regex: %s\n", complete_regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "---------------------------------------------\n");

  // cleanup
  for (i = 0; i < n; i++)
  {
    for (j = 0; j < n; j++)
      GNUNET_free_non_null (R_last[i][j]);
  }
}

/**
 * Creates a new DFA state based on a set of NFA states. Needs to be freed using
 * automaton_destroy_state.
 *
 * @param ctx context
 * @param nfa_states set of NFA states on which the DFA should be based on
 *
 * @return new DFA state
 */
static struct GNUNET_REGEX_State *
dfa_state_create (struct GNUNET_REGEX_Context *ctx,
                  struct GNUNET_REGEX_StateSet *nfa_states)
{
  struct GNUNET_REGEX_State *s;
  char *name;
  int len = 0;
  struct GNUNET_REGEX_State *cstate;
  struct Transition *ctran;
  int insert = 1;
  struct Transition *t;
  int i;

  s = GNUNET_malloc (sizeof (struct GNUNET_REGEX_State));
  s->id = ctx->state_id++;
  s->accepting = 0;
  s->marked = 0;
  s->name = NULL;
  s->scc_id = 0;
  s->index = -1;
  s->lowlink = -1;
  s->contained = 0;
  s->proof = NULL;

  if (NULL == nfa_states)
  {
    GNUNET_asprintf (&s->name, "s%i", s->id);
    return s;
  }

  s->nfa_set = nfa_states;

  if (nfa_states->len < 1)
    return s;

  // Create a name based on 'sset'
  s->name = GNUNET_malloc (sizeof (char) * 2);
  strcat (s->name, "{");
  name = NULL;

  for (i = 0; i < nfa_states->len; i++)
  {
    cstate = nfa_states->states[i];
    GNUNET_asprintf (&name, "%i,", cstate->id);

    if (NULL != name)
    {
      len = strlen (s->name) + strlen (name) + 1;
      s->name = GNUNET_realloc (s->name, len);
      strcat (s->name, name);
      GNUNET_free (name);
      name = NULL;
    }

    // Add a transition for each distinct label to NULL state
    for (ctran = cstate->transitions_head; NULL != ctran; ctran = ctran->next)
    {
      if (0 != ctran->label)
      {
        insert = 1;

        for (t = s->transitions_head; NULL != t; t = t->next)
        {
          if (t->label == ctran->label)
          {
            insert = 0;
            break;
          }
        }

        if (insert)
          state_add_transition (ctx, s, ctran->label, NULL);
      }
    }

    // If the nfa_states contain an accepting state, the new dfa state is also
    // accepting
    if (cstate->accepting)
      s->accepting = 1;
  }

  s->name[strlen (s->name) - 1] = '}';

  return s;
}

/**
 * Move from the given state 's' to the next state on transition 'label'
 *
 * @param s starting state
 * @param label edge label to follow
 *
 * @return new state or NULL, if transition on label not possible
 */
static struct GNUNET_REGEX_State *
dfa_move (struct GNUNET_REGEX_State *s, const char label)
{
  struct Transition *t;
  struct GNUNET_REGEX_State *new_s;

  if (NULL == s)
    return NULL;

  new_s = NULL;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (label == t->label)
    {
      new_s = t->to_state;
      break;
    }
  }

  return new_s;
}

/**
 * Remove all unreachable states from DFA 'a'. Unreachable states are those
 * states that are not reachable from the starting state.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_unreachable_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_State *s_next;

  // 1. unmark all states
  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  // 2. traverse dfa from start state and mark all visited states
  automaton_traverse (a, NULL, NULL);

  // 3. delete all states that were not visited
  for (s = a->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;
    if (GNUNET_NO == s->marked)
      automaton_remove_state (a, s);
  }
}

/**
 * Remove all dead states from the DFA 'a'. Dead states are those states that do
 * not transition to any other state but themselfes.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_dead_states (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct Transition *t;
  int dead;

  GNUNET_assert (DFA == a->type);

  for (s = a->states_head; NULL != s; s = s->next)
  {
    if (s->accepting)
      continue;

    dead = 1;
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->to_state && t->to_state != s)
      {
        dead = 0;
        break;
      }
    }

    if (0 == dead)
      continue;

    // state s is dead, remove it
    automaton_remove_state (a, s);
  }
}

/**
 * Merge all non distinguishable states in the DFA 'a'
 *
 * @param ctx context
 * @param a DFA automaton
 */
static void
dfa_merge_nondistinguishable_states (struct GNUNET_REGEX_Context *ctx,
                                     struct GNUNET_REGEX_Automaton *a)
{
  int i;
  int table[a->state_count][a->state_count];
  struct GNUNET_REGEX_State *s1;
  struct GNUNET_REGEX_State *s2;
  struct Transition *t1;
  struct Transition *t2;
  struct GNUNET_REGEX_State *s1_next;
  struct GNUNET_REGEX_State *s2_next;
  int change;
  int num_equal_edges;

  for (i = 0, s1 = a->states_head; i < a->state_count && NULL != s1;
       i++, s1 = s1->next)
  {
    s1->marked = i;
  }

  // Mark all pairs of accepting/!accepting states
  for (s1 = a->states_head; NULL != s1; s1 = s1->next)
  {
    for (s2 = a->states_head; NULL != s2; s2 = s2->next)
    {
      table[s1->marked][s2->marked] = 0;

      if ((s1->accepting && !s2->accepting) ||
          (!s1->accepting && s2->accepting))
      {
        table[s1->marked][s2->marked] = 1;
      }
    }
  }

  // Find all equal states
  change = 1;
  while (0 != change)
  {
    change = 0;
    for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    {
      for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
      {
        if (0 != table[s1->marked][s2->marked])
          continue;

        num_equal_edges = 0;
        for (t1 = s1->transitions_head; NULL != t1; t1 = t1->next)
        {
          for (t2 = s2->transitions_head; NULL != t2; t2 = t2->next)
          {
            if (t1->label == t2->label)
            {
              num_equal_edges++;
              if (0 != table[t1->to_state->marked][t2->to_state->marked] ||
                  0 != table[t2->to_state->marked][t1->to_state->marked])
              {
                table[s1->marked][s2->marked] = t1->label != 0 ? t1->label : 1;
                change = 1;
              }
            }
          }
        }
        if (num_equal_edges != s1->transition_count ||
            num_equal_edges != s2->transition_count)
        {
          // Make sure ALL edges of possible equal states are the same
          table[s1->marked][s2->marked] = -2;
        }
      }
    }
  }

  // Merge states that are equal
  for (s1 = a->states_head; NULL != s1; s1 = s1_next)
  {
    s1_next = s1->next;
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2_next)
    {
      s2_next = s2->next;
      if (table[s1->marked][s2->marked] == 0)
        automaton_merge_states (ctx, a, s1, s2);
    }
  }
}

/**
 * Minimize the given DFA 'a' by removing all unreachable states, removing all
 * dead states and merging all non distinguishable states
 *
 * @param ctx context
 * @param a DFA automaton
 */
static void
dfa_minimize (struct GNUNET_REGEX_Context *ctx,
              struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return;

  GNUNET_assert (DFA == a->type);

  // 1. remove unreachable states
  dfa_remove_unreachable_states (a);

  // 2. remove dead states
  dfa_remove_dead_states (a);

  // 3. Merge nondistinguishable states
  dfa_merge_nondistinguishable_states (ctx, a);
}

/**
 * Creates a new NFA fragment. Needs to be cleared using
 * automaton_fragment_clear.
 *
 * @param start starting state
 * @param end end state
 *
 * @return new NFA fragment
 */
static struct GNUNET_REGEX_Automaton *
nfa_fragment_create (struct GNUNET_REGEX_State *start,
                     struct GNUNET_REGEX_State *end)
{
  struct GNUNET_REGEX_Automaton *n;

  n = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));

  n->type = NFA;
  n->start = NULL;
  n->end = NULL;

  if (NULL == start && NULL == end)
    return n;

  automaton_add_state (n, end);
  automaton_add_state (n, start);

  n->start = start;
  n->end = end;

  return n;
}

/**
 * Adds a list of states to the given automaton 'n'.
 *
 * @param n automaton to which the states should be added
 * @param states_head head of the DLL of states
 * @param states_tail tail of the DLL of states
 */
static void
nfa_add_states (struct GNUNET_REGEX_Automaton *n,
                struct GNUNET_REGEX_State *states_head,
                struct GNUNET_REGEX_State *states_tail)
{
  struct GNUNET_REGEX_State *s;

  if (NULL == n || NULL == states_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not add states\n");
    return;
  }

  if (NULL == n->states_head)
  {
    n->states_head = states_head;
    n->states_tail = states_tail;
    return;
  }

  if (NULL != states_head)
  {
    n->states_tail->next = states_head;
    n->states_tail = states_tail;
  }

  for (s = states_head; NULL != s; s = s->next)
    n->state_count++;
}

/**
 * Creates a new NFA state. Needs to be freed using automaton_destroy_state.
 *
 * @param ctx context
 * @param accepting is it an accepting state or not
 *
 * @return new NFA state
 */
static struct GNUNET_REGEX_State *
nfa_state_create (struct GNUNET_REGEX_Context *ctx, int accepting)
{
  struct GNUNET_REGEX_State *s;

  s = GNUNET_malloc (sizeof (struct GNUNET_REGEX_State));
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->marked = 0;
  s->contained = 0;
  s->index = -1;
  s->lowlink = -1;
  s->scc_id = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}

/**
 * Calculates the NFA closure set for the given state.
 *
 * @param nfa the NFA containing 's'
 * @param s starting point state
 * @param label transitioning label on which to base the closure on,
 *                pass 0 for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is 0)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_create (struct GNUNET_REGEX_Automaton *nfa,
                    struct GNUNET_REGEX_State *s, const char label)
{
  struct GNUNET_REGEX_StateSet *cls;
  struct GNUNET_REGEX_StateSet *cls_check;
  struct GNUNET_REGEX_State *clsstate;
  struct GNUNET_REGEX_State *currentstate;
  struct Transition *ctran;

  if (NULL == s)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));
  cls_check = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));

  for (clsstate = nfa->states_head; NULL != clsstate; clsstate = clsstate->next)
    clsstate->contained = 0;

  // Add start state to closure only for epsilon closure
  if (0 == label)
    GNUNET_array_append (cls->states, cls->len, s);

  GNUNET_array_append (cls_check->states, cls_check->len, s);
  while (cls_check->len > 0)
  {
    currentstate = cls_check->states[cls_check->len - 1];
    GNUNET_array_grow (cls_check->states, cls_check->len, cls_check->len - 1);

    for (ctran = currentstate->transitions_head; NULL != ctran;
         ctran = ctran->next)
    {
      if (NULL != ctran->to_state && label == ctran->label)
      {
        clsstate = ctran->to_state;

        if (NULL != clsstate && 0 == clsstate->contained)
        {
          GNUNET_array_append (cls->states, cls->len, clsstate);
          GNUNET_array_append (cls_check->states, cls_check->len, clsstate);
          clsstate->contained = 1;
        }
      }
    }
  }
  GNUNET_assert (0 == cls_check->len);
  GNUNET_free (cls_check);

  // sort the states
  if (cls->len > 1)
    qsort (cls->states, cls->len, sizeof (struct GNUNET_REGEX_State *),
           state_compare);

  return cls;
}

/**
 * Calculates the closure set for the given set of states.
 *
 * @param nfa the NFA containing 's'
 * @param states list of states on which to base the closure on
 * @param label transitioning label for which to base the closure on,
 *                pass 0 for epsilon transition
 *
 * @return sorted nfa closure on 'label' (epsilon closure if 'label' is 0)
 */
static struct GNUNET_REGEX_StateSet *
nfa_closure_set_create (struct GNUNET_REGEX_Automaton *nfa,
                        struct GNUNET_REGEX_StateSet *states, const char label)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *cls;
  int i;
  int j;
  int k;
  int contains;

  if (NULL == states)
    return NULL;

  cls = GNUNET_malloc (sizeof (struct GNUNET_REGEX_StateSet));

  for (i = 0; i < states->len; i++)
  {
    s = states->states[i];
    sset = nfa_closure_create (nfa, s, label);

    for (j = 0; j < sset->len; j++)
    {
      contains = 0;
      for (k = 0; k < cls->len; k++)
      {
        if (sset->states[j]->id == cls->states[k]->id)
        {
          contains = 1;
          break;
        }
      }
      if (!contains)
        GNUNET_array_append (cls->states, cls->len, sset->states[j]);
    }
    state_set_clear (sset);
  }

  if (cls->len > 1)
    qsort (cls->states, cls->len, sizeof (struct GNUNET_REGEX_State *),
           state_compare);

  return cls;
}

/**
 * Pops two NFA fragments (a, b) from the stack and concatenates them (ab)
 *
 * @param ctx context
 */
static void
nfa_add_concatenation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, 0, b->start);
  a->end->accepting = 0;
  b->end->accepting = 1;

  new = nfa_fragment_create (NULL, NULL);
  nfa_add_states (new, a->states_head, a->states_tail);
  nfa_add_states (new, b->states_head, b->states_tail);
  new->start = a->start;
  new->end = b->end;
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
}

/**
 * Pops a NFA fragment from the stack (a) and adds a new fragment (a*)
 *
 * @param ctx context
 */
static void
nfa_add_star_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *new;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, end);
  state_add_transition (ctx, a->end, 0, a->start);
  state_add_transition (ctx, a->end, 0, end);

  a->end->accepting = 0;
  end->accepting = 1;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
}

/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a+)
 *
 * @param ctx context
 */
static void
nfa_add_plus_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, 0, a->start);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, a);
}

/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a?)
 *
 * @param ctx context
 */
static void
nfa_add_question_op (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *new;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_question_op failed, because there was no element on the stack");
    return;
  }

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, end);
  state_add_transition (ctx, a->end, 0, end);

  a->end->accepting = 0;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
}

/**
 * Pops two NFA fragments (a, b) from the stack and adds a new NFA fragment that
 * alternates between a and b (a|b)
 *
 * @param ctx context
 */
static void
nfa_add_alternation (struct GNUNET_REGEX_Context *ctx)
{
  struct GNUNET_REGEX_Automaton *a;
  struct GNUNET_REGEX_Automaton *b;
  struct GNUNET_REGEX_Automaton *new;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  b = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, 0, a->start);
  state_add_transition (ctx, start, 0, b->start);

  state_add_transition (ctx, a->end, 0, end);
  state_add_transition (ctx, b->end, 0, end);

  a->end->accepting = 0;
  b->end->accepting = 0;
  end->accepting = 1;

  new = nfa_fragment_create (start, end);
  nfa_add_states (new, a->states_head, a->states_tail);
  nfa_add_states (new, b->states_head, b->states_tail);
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new);
}

/**
 * Adds a new nfa fragment to the stack
 *
 * @param ctx context
 * @param lit label for nfa transition
 */
static void
nfa_add_label (struct GNUNET_REGEX_Context *ctx, const char lit)
{
  struct GNUNET_REGEX_Automaton *n;
  struct GNUNET_REGEX_State *start;
  struct GNUNET_REGEX_State *end;

  GNUNET_assert (NULL != ctx);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, lit, end);
  n = nfa_fragment_create (start, end);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, n);
}

/**
 * Initialize a new context
 *
 * @param ctx context
 */
static void
GNUNET_REGEX_context_init (struct GNUNET_REGEX_Context *ctx)
{
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Context was NULL!");
    return;
  }
  ctx->state_id = 0;
  ctx->transition_id = 0;
  ctx->stack_head = NULL;
  ctx->stack_tail = NULL;
}

/**
 * Construct an NFA by parsing the regex string of length 'len'.
 *
 * @param regex regular expression string
 * @param len length of the string
 *
 * @return NFA, needs to be freed using GNUNET_REGEX_destroy_automaton
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_nfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *nfa;
  const char *regexp;
  char *error_msg;
  unsigned int count;
  unsigned int altcount;
  unsigned int atomcount;
  unsigned int pcount;
  struct
  {
    int altcount;
    int atomcount;
  }     *p;

  GNUNET_REGEX_context_init (&ctx);

  regexp = regex;
  p = NULL;
  error_msg = NULL;
  altcount = 0;
  atomcount = 0;
  pcount = 0;

  for (count = 0; count < len && *regexp; count++, regexp++)
  {
    switch (*regexp)
    {
    case '(':
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      GNUNET_array_grow (p, pcount, pcount + 1);
      p[pcount - 1].altcount = altcount;
      p[pcount - 1].atomcount = atomcount;
      altcount = 0;
      atomcount = 0;
      break;
    case '|':
      if (0 == atomcount)
      {
        error_msg = "Cannot append '|' to nothing";
        goto error;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      altcount++;
      break;
    case ')':
      if (0 == pcount)
      {
        error_msg = "Missing opening '('";
        goto error;
      }
      if (0 == atomcount)
      {
        // Ignore this: "()"
        pcount--;
        altcount = p[pcount].altcount;
        atomcount = p[pcount].atomcount;
        break;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      for (; altcount > 0; altcount--)
        nfa_add_alternation (&ctx);
      pcount--;
      altcount = p[pcount].altcount;
      atomcount = p[pcount].atomcount;
      atomcount++;
      break;
    case '*':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '*' to nothing";
        goto error;
      }
      nfa_add_star_op (&ctx);
      break;
    case '+':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '+' to nothing";
        goto error;
      }
      nfa_add_plus_op (&ctx);
      break;
    case '?':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '?' to nothing";
        goto error;
      }
      nfa_add_question_op (&ctx);
      break;
    case 92:                   /* escape: \ */
      regexp++;
      count++;
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      nfa_add_label (&ctx, *regexp);
      atomcount++;
      break;
    }
  }
  if (0 != pcount)
  {
    error_msg = "Unbalanced parenthesis";
    goto error;
  }
  while (--atomcount > 0)
    nfa_add_concatenation (&ctx);
  for (; altcount > 0; altcount--)
    nfa_add_alternation (&ctx);

  GNUNET_free_non_null (p);

  nfa = ctx.stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);

  if (NULL != ctx.stack_head)
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  nfa->regex = GNUNET_strdup (regex);

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex: %s\n", regex);
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);

  GNUNET_free_non_null (p);

  while (NULL != (nfa = ctx.stack_head))
  {
    GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);
    GNUNET_REGEX_automaton_destroy (nfa);
  }

  return NULL;
}

/**
 * Create DFA states based on given 'nfa' and starting with 'dfa_state'.
 *
 * @param ctx context.
 * @param nfa NFA automaton.
 * @param dfa DFA automaton.
 * @param dfa_state current dfa state, pass epsilon closure of first nfa state
 *                  for starting.
 */
static void
construct_dfa_states (struct GNUNET_REGEX_Context *ctx,
                      struct GNUNET_REGEX_Automaton *nfa,
                      struct GNUNET_REGEX_Automaton *dfa,
                      struct GNUNET_REGEX_State *dfa_state)
{
  struct Transition *ctran;
  struct GNUNET_REGEX_State *state_iter;
  struct GNUNET_REGEX_State *new_dfa_state;
  struct GNUNET_REGEX_State *state_contains;
  struct GNUNET_REGEX_StateSet *tmp;
  struct GNUNET_REGEX_StateSet *nfa_set;

  for (ctran = dfa_state->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (0 == ctran->label || NULL != ctran->to_state)
      continue;

    tmp = nfa_closure_set_create (nfa, dfa_state->nfa_set, ctran->label);
    nfa_set = nfa_closure_set_create (nfa, tmp, 0);
    state_set_clear (tmp);
    new_dfa_state = dfa_state_create (ctx, nfa_set);
    state_contains = NULL;
    for (state_iter = dfa->states_head; NULL != state_iter;
         state_iter = state_iter->next)
    {
      if (0 == state_set_compare (state_iter->nfa_set, new_dfa_state->nfa_set))
        state_contains = state_iter;
    }

    if (NULL == state_contains)
    {
      automaton_add_state (dfa, new_dfa_state);
      ctran->to_state = new_dfa_state;
      construct_dfa_states (ctx, nfa, dfa, new_dfa_state);
    }
    else
    {
      ctran->to_state = state_contains;
      automaton_destroy_state (new_dfa_state);
    }
  }
}

/**
 * Construct DFA for the given 'regex' of length 'len'
 *
 * @param regex regular expression string
 * @param len length of the regular expression
 *
 * @return DFA, needs to be freed using GNUNET_REGEX_destroy_automaton
 */
struct GNUNET_REGEX_Automaton *
GNUNET_REGEX_construct_dfa (const char *regex, const size_t len)
{
  struct GNUNET_REGEX_Context ctx;
  struct GNUNET_REGEX_Automaton *dfa;
  struct GNUNET_REGEX_Automaton *nfa;
  struct GNUNET_REGEX_StateSet *nfa_set;

  GNUNET_REGEX_context_init (&ctx);

  // Create NFA
  nfa = GNUNET_REGEX_construct_nfa (regex, len);

  if (NULL == nfa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create DFA, because NFA creation failed\n");
    return NULL;
  }

  dfa = GNUNET_malloc (sizeof (struct GNUNET_REGEX_Automaton));
  dfa->type = DFA;
  dfa->regex = GNUNET_strdup (regex);

  // Create DFA start state from epsilon closure
  nfa_set = nfa_closure_create (nfa, nfa->start, 0);
  dfa->start = dfa_state_create (&ctx, nfa_set);
  automaton_add_state (dfa, dfa->start);

  construct_dfa_states (&ctx, nfa, dfa, dfa->start);

  GNUNET_REGEX_automaton_destroy (nfa);

  // Minimize DFA
  dfa_minimize (&ctx, dfa);

  // Create proofs for all states
  automaton_create_proofs (dfa);

  return dfa;
}

/**
 * Free the memory allocated by constructing the GNUNET_REGEX_Automaton data
 * structure.
 *
 * @param a automaton to be destroyed
 */
void
GNUNET_REGEX_automaton_destroy (struct GNUNET_REGEX_Automaton *a)
{
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_State *next_state;

  if (NULL == a)
    return;

  GNUNET_free_non_null (a->regex);
  GNUNET_free_non_null (a->computed_regex);

  for (s = a->states_head; NULL != s;)
  {
    next_state = s->next;
    automaton_destroy_state (s);
    s = next_state;
  }

  GNUNET_free (a);
}

/**
 * Save a state to an open file pointer. cls is expected to be a file pointer to
 * an open file. Used only in conjunction with
 * GNUNET_REGEX_automaton_save_graph.
 *
 * @param cls file pointer.
 * @param count current count of the state, not used.
 * @param s state.
 */
void
GNUNET_REGEX_automaton_save_graph_step (void *cls, unsigned int count,
                                        struct GNUNET_REGEX_State *s)
{
  FILE *p;
  struct Transition *ctran;
  char *s_acc = NULL;
  char *s_tran = NULL;

  p = cls;

  if (s->accepting)
  {
    GNUNET_asprintf (&s_acc,
                     "\"%s(%i)\" [shape=doublecircle, color=\"0.%i 0.8 0.95\"];\n",
                     s->name, s->proof_id, s->scc_id);
  }
  else
  {
    GNUNET_asprintf (&s_acc, "\"%s(%i)\" [color=\"0.%i 0.8 0.95\"];\n", s->name,
                     s->proof_id, s->scc_id);
  }

  if (NULL == s_acc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print state %s\n", s->name);
    return;
  }
  fwrite (s_acc, strlen (s_acc), 1, p);
  GNUNET_free (s_acc);
  s_acc = NULL;

  for (ctran = s->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (NULL == ctran->to_state)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Transition from State %i has no state for transitioning\n",
                  s->id);
      continue;
    }

    if (ctran->label == 0)
    {
      GNUNET_asprintf (&s_tran,
                       "\"%s(%i)\" -> \"%s(%i)\" [label = \"epsilon\", color=\"0.%i 0.8 0.95\"];\n",
                       s->name, s->proof_id, ctran->to_state->name,
                       ctran->to_state->proof_id, s->scc_id);
    }
    else
    {
      GNUNET_asprintf (&s_tran,
                       "\"%s(%i)\" -> \"%s(%i)\" [label = \"%c\", color=\"0.%i 0.8 0.95\"];\n",
                       s->name, s->proof_id, ctran->to_state->name,
                       ctran->to_state->proof_id, ctran->label, s->scc_id);
    }

    if (NULL == s_tran)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print state %s\n",
                  s->name);
      return;
    }

    fwrite (s_tran, strlen (s_tran), 1, p);
    GNUNET_free (s_tran);
    s_tran = NULL;
  }
}

/**
 * Save the given automaton as a GraphViz dot file
 *
 * @param a the automaton to be saved
 * @param filename where to save the file
 */
void
GNUNET_REGEX_automaton_save_graph (struct GNUNET_REGEX_Automaton *a,
                                   const char *filename)
{
  char *start;
  char *end;
  FILE *p;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not print NFA, was NULL!");
    return;
  }

  if (NULL == filename || strlen (filename) < 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No Filename given!");
    return;
  }

  p = fopen (filename, "w");

  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not open file for writing: %s",
                filename);
    return;
  }

  /* First add the SCCs to the automaton, so we can color them nicely */
  scc_tarjan (a);

  start = "digraph G {\nrankdir=LR\n";
  fwrite (start, strlen (start), 1, p);

  automaton_traverse (a, &GNUNET_REGEX_automaton_save_graph_step, p);

  end = "\n}\n";
  fwrite (end, strlen (end), 1, p);
  fclose (p);
}

/**
 * Evaluates the given string using the given DFA automaton
 *
 * @param a automaton, type must be DFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_dfa (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  const char *strp;
  struct GNUNET_REGEX_State *s;

  if (DFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate DFA, but NFA automaton given");
    return -1;
  }

  s = a->start;

  // If the string is empty but the starting state is accepting, we accept.
  if ((NULL == string || 0 == strlen (string)) && s->accepting)
    return 0;

  for (strp = string; NULL != strp && *strp; strp++)
  {
    s = dfa_move (s, *strp);
    if (NULL == s)
      break;
  }

  if (NULL != s && s->accepting)
    return 0;

  return 1;
}

/**
 * Evaluates the given string using the given NFA automaton
 *
 * @param a automaton, type must be NFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_nfa (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  const char *strp;
  struct GNUNET_REGEX_State *s;
  struct GNUNET_REGEX_StateSet *sset;
  struct GNUNET_REGEX_StateSet *new_sset;
  int i;
  int result;

  if (NFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate NFA, but DFA automaton given");
    return -1;
  }

  // If the string is empty but the starting state is accepting, we accept.
  if ((NULL == string || 0 == strlen (string)) && a->start->accepting)
    return 0;

  result = 1;
  strp = string;
  sset = nfa_closure_create (a, a->start, 0);

  for (strp = string; NULL != strp && *strp; strp++)
  {
    new_sset = nfa_closure_set_create (a, sset, *strp);
    state_set_clear (sset);
    sset = nfa_closure_set_create (a, new_sset, 0);
    state_set_clear (new_sset);
  }

  for (i = 0; i < sset->len; i++)
  {
    s = sset->states[i];
    if (NULL != s && s->accepting)
    {
      result = 0;
      break;
    }
  }

  state_set_clear (sset);
  return result;
}

/**
 * Evaluates the given 'string' against the given compiled regex
 *
 * @param a automaton
 * @param string string to check
 *
 * @return 0 if string matches, non 0 otherwise
 */
int
GNUNET_REGEX_eval (struct GNUNET_REGEX_Automaton *a, const char *string)
{
  int result;

  switch (a->type)
  {
  case DFA:
    result = evaluate_dfa (a, string);
    break;
  case NFA:
    result = evaluate_nfa (a, string);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Evaluating regex failed, automaton has no type!\n");
    result = GNUNET_SYSERR;
    break;
  }

  return result;
}

/**
 * Get the computed regex of the given automaton.
 * When constructing the automaton a proof is computed for each state,
 * consisting of the regular expression leading to this state. A complete
 * regex for the automaton can be computed by combining these proofs.
 * As of now this computed regex is only useful for testing.
 */
const char *
GNUNET_REGEX_get_computed_regex (struct GNUNET_REGEX_Automaton *a)
{
  if (NULL == a)
    return NULL;

  return a->computed_regex;
}

/**
 * Get the first key for the given 'input_string'. This hashes the first x bits
 * of the 'input_strings'.
 *
 * @param input_string string.
 * @param string_len length of the 'input_string'.
 * @param key pointer to where to write the hash code.
 *
 * @return number of bits of 'input_string' that have been consumed
 *         to construct the key
 */
unsigned int
GNUNET_REGEX_get_first_key (const char *input_string, unsigned int string_len,
                            struct GNUNET_HashCode *key)
{
  unsigned int size;

  size = string_len < INITIAL_BITS ? string_len : INITIAL_BITS;

  if (NULL == input_string)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Given input string was NULL!\n");
    return 0;
  }

  GNUNET_CRYPTO_hash (input_string, size, key);

  return size;
}

/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex
 * @param key hash
 *
 * @return GNUNET_OK if the proof is valid for the given key
 */
int
GNUNET_REGEX_check_proof (const char *proof, const struct GNUNET_HashCode *key)
{
  return GNUNET_OK;
}

/**
 * Iterate over all edges helper function starting from state 's', calling
 * iterator on for each edge.
 *
 * @param s state.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure.
 */
static void
iterate_edge (struct GNUNET_REGEX_State *s, GNUNET_REGEX_KeyIterator iterator,
              void *iterator_cls)
{
  struct Transition *t;
  struct GNUNET_REGEX_Edge edges[s->transition_count];
  unsigned int num_edges;

  if (GNUNET_YES != s->marked)
  {
    s->marked = GNUNET_YES;

    num_edges = state_get_edges (s, edges);

    iterator (iterator_cls, &s->hash, s->proof, s->accepting, num_edges, edges);

    for (t = s->transitions_head; NULL != t; t = t->next)
      iterate_edge (t->to_state, iterator, iterator_cls);
  }
}

/**
 * Iterate over all edges starting from start state of automaton 'a'. Calling
 * iterator for each edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each edge.
 * @param iterator_cls closure.
 */
void
GNUNET_REGEX_iterate_all_edges (struct GNUNET_REGEX_Automaton *a,
                                GNUNET_REGEX_KeyIterator iterator,
                                void *iterator_cls)
{
  struct GNUNET_REGEX_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  iterate_edge (a->start, iterator, iterator_cls);
}
