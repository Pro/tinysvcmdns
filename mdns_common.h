//
// Created by profanter on 19.07.16.
//

#ifndef MDNS_MDNS_COMMON_H
#define MDNS_MDNS_COMMON_H

/**
 * Function Export
 * --------------- */
#ifdef _WIN32
# ifdef MDNS_DYNAMIC_LINKING
#  ifdef __GNUC__
#   define MDNS_EXPORT __attribute__ ((dllexport))
#  else
#   define MDNS_EXPORT __declspec(dllexport)
#  endif
# else
#  ifdef __GNUC__
#   define MDNS_EXPORT __attribute__ ((dllexport))
#  else
#   define MDNS_EXPORT __declspec(dllimport)
#  endif
# endif
#else
# if __GNUC__ || __clang__
#  define MDNS_EXPORT __attribute__ ((visibility ("default")))
# else
#  define MDNS_EXPORT
# endif
#endif

#endif //MDNS_MDNS_COMMON_H
