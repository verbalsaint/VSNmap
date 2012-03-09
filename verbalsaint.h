//#pragma once
#ifndef VERBALSAINT_H
#define VERBALSAINT_H
#include "verbalsaintdef.h"
#define VERBALSAINT_INNER(X)	namespace VERBALSAINT{ namespace X{
#define VERBALSAINT_INNER_END(X)	}}

#define VERBALSAINT_NS	namespace VERBALSAINT{
#define VERBALSAINT_NS_END	}

#define UV(X)	using namespace VERBALSAINT::X;
#define UVs()	using namespace VERBALSAINT;

#define BUDDHA namespace { const char* Buddha = "一切有為法 如夢幻泡影 如露亦如電 應做如是觀"; }

#endif // VERBALSAINT_H
