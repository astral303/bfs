// Copyright © Tavian Barnes <tavianator@tavianator.com>
// SPDX-License-Identifier: 0BSD

#include <sys/attr.h>
#include <unistd.h>

int main(void) {
	struct attrlist attrs = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME,
	};
	char buf[1024];
	return getattrlistbulk(3, &attrs, buf, sizeof(buf), 0);
}
