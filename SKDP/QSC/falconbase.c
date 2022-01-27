#include "falconbase.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

/*
	Removed macros and unions and other MISRA violations.
	Reformatted code, removed unused functions, made memory optimizations,
	and formatted for a single file implementation  -JGU
*/

/* fpr.c */

static uint64_t falcon_fpr_ursh(uint64_t x, int32_t n)
{
	/*
	* Right-shift a 64-bit uint32_t value by a possibly secret shift count.
	* We assumed that the underlying architecture had a barrel shifter for
	* 32-bit shifts, but for 64-bit shifts on a 32-bit system, this will
	* typically invoke a software routine that is not necessarily
	* constant-time; hence the function below.
	*
	* Shift count n MUST be in the 0..63 range.
	*/

	x ^= (x ^ (x >> 32)) & (uint64_t)-(int64_t)(n >> 5);

	return x >> (n & 31);
}

static int64_t falcon_fpr_irsh(int64_t x, int32_t n)
{
	/*
	 * Right-shift a 64-bit signed value by a possibly secret shift count
	 * (see falcon_fpr_ursh() for the rationale).
	 *
	 * Shift count n MUST be in the 0..63 range.
	 */

	x ^= (x ^ (x >> 32)) & -(int64_t)(n >> 5);

	return x >> (n & 31);
}

static uint64_t falcon_fpr_ulsh(uint64_t x, int32_t n)
{
	/*
	* Left-shift a 64-bit uint32_t value by a possibly secret shift count
	* (see falcon_fpr_ursh() for the rationale).
	*
	* Shift count n MUST be in the 0..63 range.
	*/

	x ^= (x ^ (x << 32)) & (uint64_t)-(int64_t)(n >> 5);

	return x << (n & 31);
}

static falcon_fpr falcon_FPR(int32_t s, int32_t e, uint64_t m)
{
	/*
	 * Expectations:
	 *   s = 0 or 1
	 *   exponent e is "arbitrary" and unbiased
	 *   2^54 <= m < 2^55
	 * Numerical value is (-1)^2 * m * 2^e
	 *
	 * Exponents which are too low lead to value zero. If the exponent is
	 * too large, the returned value is indeterminate.
	 *
	 * If m = 0, then a zero is returned (using the provided sign).
	 * If e < -1076, then a zero is returned (regardless of the value of m).
	 * If e >= -1076 and e != 0, m must be within the expected range
	 * (2^54 to 2^55-1).
	 */

	falcon_fpr x;
	uint32_t t;
	uint32_t f;

	/*
	 * If e >= -1076, then the value is "normal"; otherwise, it
	 * should be a subnormal, which we clamp down to zero.
	 */
	e += 1076;
	t = (uint32_t)e >> 31;
	m &= (uint64_t)t - 1;

	/*
	 * If m = 0 then we want a zero; make e = 0 too, but conserve
	 * the sign.
	 */
	t = (uint32_t)(m >> 54);
	e &= -(int32_t)t;

	/*
	 * The 52 mantissa bits come from m. Value m has its top bit set
	 * (unless it is a zero); we leave it "as is": the top bit will
	 * increment the exponent by 1, except when m = 0, which is
	 * exactly what we want.
	 */
	x = (((uint64_t)s << 63) | (m >> 2)) + ((uint64_t)(uint32_t)e << 52);

	/*
	 * Rounding: if the low three bits of m are 011, 110 or 111,
	 * then the value should be incremented to get the next
	 * representable value. This implements the usual
	 * round-to-nearest rule (with preference to even values in case
	 * of a tie). Note that the increment may make a carry spill
	 * into the exponent field, which is again exactly what we want
	 * in that case.
	 */
	f = (uint32_t)m & 7U;
	x += (0x0000000000000C8ULL >> f) & 1;

	return x;
}

static falcon_fpr falcon_fpr_neg(falcon_fpr x)
{
	x ^= 1ULL << 63;

	return x;
}

static falcon_fpr falcon_fpr_half(falcon_fpr x)
{
	/*
	 * To divide a value by 2, we just have to subtract 1 from its
	 * exponent, but we have to take care of zero.
	 */
	uint32_t t;

	x -= 1ULL << 52;
	t = (((uint32_t)(x >> 52) & 0x000007FFUL) + 1) >> 11;
	x &= (uint64_t)t - 1;

	return x;
}

static int64_t falcon_fpr_rint(falcon_fpr x)
{
	uint64_t d;
	uint64_t m;
	uint32_t dd;
	uint32_t f;
	uint32_t s;
	int32_t e;

	/*
	 * We assume that the value fits in -(2^63-1)..+(2^63-1). We can
	 * thus extract the mantissa as a 63-bit integer, then right-shift
	 * it as needed.
	 */
	m = ((x << 10) | (1ULL << 62)) & ((1ULL << 63) - 1);
	e = 1085 - ((int32_t)(x >> 52) & 0x000007FFUL);

	/*
	 * If a shift of more than 63 bits is needed, then simply set m
	 * to zero. This also covers the case of an input operand equal
	 * to zero.
	 */
	m &= ~(uint64_t)((uint32_t)(e - 64) >> 31) + 1;
	e &= 63;

	/*
	 * Right-shift m as needed. Shift count is e. Proper rounding
	 * mandates that:
	 *   - If the highest dropped bit is zero, then round low.
	 *   - If the highest dropped bit is one, and at least one of the
	 *     other dropped bits is one, then round up.
	 *   - If the highest dropped bit is one, and all other dropped
	 *     bits are zero, then round up if the lowest kept bit is 1,
	 *     or low otherwise (i.e. ties are broken by "rounding to even").
	 *
	 * We thus first extract a word consisting of all the dropped bit
	 * AND the lowest kept bit; then we shrink it down to three bits,
	 * the lowest being "sticky".
	 */
	d = falcon_fpr_ulsh(m, 63 - e);
	dd = (uint32_t)d | ((uint32_t)(d >> 32) & 0x1FFFFFFFULL);
	f = (uint32_t)(d >> 61) | ((dd | (uint32_t)-(int32_t)dd) >> 31);
	m = falcon_fpr_ursh(m, e) + ((0x0000000000000C8ULL >> f) & 1U);

	/*
	 * Apply the sign bit.
	 */
	s = (uint32_t)(x >> 63);

	return ((int64_t)m ^ -(int64_t)s) + (int64_t)s;
}

static int64_t falcon_fpr_floor(falcon_fpr x)
{
	uint64_t t;
	int64_t xi;
	int32_t e;
	int32_t cc;

	/*
	 * We extract the integer as a _signed_ 64-bit integer with
	 * a scaling factor. Since we assume that the value fits
	 * in the -(2^63-1)..+(2^63-1) range, we can left-shift the
	 * absolute value to make it in the 2^62..2^63-1 range: we
	 * will only need a right-shift afterwards.
	 */
	e = (int32_t)(x >> 52) & 0x000007FFL;
	t = x >> 63;
	xi = (int64_t)(((x << 10) | (1ULL << 62)) & ((1ULL << 63) - 1));
	xi = (xi ^ -(int64_t)t) + (int64_t)t;
	cc = 1085 - e;

	/*
	 * We perform an arithmetic right-shift on the value. This
	 * applies floor() semantics on both positive and negative values
	 * (rounding toward minus infinity).
	 */
	xi = falcon_fpr_irsh(xi, cc & 63);

	/*
	 * If the true shift count was 64 or more, then we should instead
	 * replace xi with 0 (if nonnegative) or -1 (if negative). Edge
	 * case: -0 will be floored to -1, not 0 (whether this is correct
	 * is debatable; in any case, the other functions normalize zero
	 * to +0).
	 *
	 * For an input of zero, the non-shifted xi was incorrect (we used
	 * a top implicit bit of value 1, not 0), but this does not matter
	 * since this operation will clamp it down.
	 */
	xi ^= (xi ^ -(int64_t)t) & -(int64_t)((uint32_t)(63 - cc) >> 31);

	return xi;
}

static int64_t falcon_fpr_trunc(falcon_fpr x)
{
	uint64_t t;
	uint64_t xu;
	int32_t cc;
	int32_t e;

	/*
	 * Extract the absolute value. Since we assume that the value
	 * fits in the -(2^63-1)..+(2^63-1) range, we can left-shift
	 * the absolute value into the 2^62..2^63-1 range, and then
	 * do a right shift afterwards.
	 */
	e = (int32_t)(x >> 52) & 0x000007FFL;
	xu = ((x << 10) | (1ULL << 62)) & ((1ULL << 63) - 1);
	cc = 1085 - e;
	xu = falcon_fpr_ursh(xu, cc & 63);

	/*
	 * If the exponent is too low (cc > 63), then the shift was wrong
	 * and we must clamp the value to 0. This also covers the case
	 * of an input equal to zero.
	 */
	xu &= ~(uint64_t)((uint32_t)(cc - 64) >> 31) + 1;

	/*
	 * Apply back the sign, if the source value is negative.
	 */
	t = x >> 63;
	xu = (xu ^ (~t + 1)) + t;

	return *(int64_t *)&xu;
}

static int32_t falcon_fpr_lt(falcon_fpr x, falcon_fpr y)
{
	/*
	 * If x >= 0 or y >= 0, a signed comparison yields the proper
	 * result:
	 *   - For positive values, the order is preserved.
	 *   - The sign bit is at the same place as in integers, so
	 *     sign is preserved.
	 *
	 * If both x and y are negative, then the order is reversed.
	 * We cannot simply invert the comparison result in that case
	 * because it would not handle the edge case x = y properly.
	 */
	int32_t cc0;
	int32_t cc1;

	cc0 = *(int64_t *)&x < *(int64_t*)&y;
	cc1 = *(int64_t *)&x > *(int64_t*)&y;

	return cc0 ^ ((cc0 ^ cc1) & (int32_t)((x & y) >> 63));
}

static void falcon_fpr_norm64(uint64_t* m, int32_t* e)
{
	uint32_t nt;

	*e -= 63;
	nt = (uint32_t)(*m >> 32);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 32)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 5);

	nt = (uint32_t)(*m >> 48);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 16)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 4);

	nt = (uint32_t)(*m >> 56);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 8)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 3);

	nt = (uint32_t)(*m >> 60);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 4)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 2);

	nt = (uint32_t)(*m >> 62);
	nt = (nt | (uint32_t)-(int32_t)nt) >> 31;
	*m ^= (*m ^ (*m << 2)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt << 1);

	nt = (uint32_t)(*m >> 63);
	*m ^= (*m ^ (*m << 1)) & ((uint64_t)nt - 1);
	*e += (int32_t)(nt);
}

static falcon_fpr falcon_fpr_scaled(int64_t i, int32_t sc)
{
	/*
	 * To convert from int32_t to float, we have to do the following:
	 *  1. Get the absolute value of the input, and its sign
	 *  2. Shift right or left the value as appropriate
	 *  3. Pack the result
	 *
	 * We can assume that the source integer is not -2^63.
	 */

	uint64_t m;
	uint32_t t;
	int32_t e;
	int32_t s;

	/*
	 * Extract sign bit.
	 * We have: -i = 1 + ~i
	 */
	s = (int32_t)((uint64_t)i >> 63);
	i ^= -(int64_t)s;
	i += s;

	/*
	 * For now we suppose that i != 0.
	 * Otherwise, we set m to i and left-shift it as much as needed
	 * to get a 1 in the top bit. We can do that in a logarithmic
	 * number of conditional shifts.
	 */
	m = (uint64_t)i;
	e = 9 + sc;
	falcon_fpr_norm64(&m, &e);

	/*
	 * Now m is in the 2^63..2^64-1 range. We must divide it by 512
	 * if one of the dropped bits is a 1, this should go into the
	 * "sticky bit".
	 */
	m |= ((uint32_t)m & 0x000001FFUL) + 0x000001FFUL;
	m >>= 9;

	/*
	 * Corrective action: if i = 0 then all of the above was
	 * incorrect, and we clamp e and m down to zero.
	 */
	t = (uint32_t)((uint64_t)(i | -i) >> 63);
	m &= (uint64_t)-(int64_t)t;
	e &= -(int32_t)t;

	/*
	 * Assemble back everything. The falcon_FPR() function will handle cases
	 * where e is too low.
	 */
	return falcon_FPR(s, e, m);
}

static falcon_fpr falcon_fpr_of(int64_t i)
{
	return falcon_fpr_scaled(i, 0);
}

static falcon_fpr falcon_fpr_add(falcon_fpr x, falcon_fpr y)
{
	uint64_t m;
	uint64_t xu;
	uint64_t yu;
	uint64_t za;
	uint32_t cs;
	int32_t cc;
	int32_t ex;
	int32_t ey;
	int32_t sx;
	int32_t sy;

	/*
	 * Make sure that the first operand (x) has the larger absolute
	 * value. This guarantees that the exponent of y is less than
	 * or equal to the exponent of x, and, if they are equal, then
	 * the mantissa of y will not be greater than the mantissa of x.
	 *
	 * After this swap, the result will have the sign x, except in
	 * the following edge case: abs(x) = abs(y), and x and y have
	 * opposite sign bits; in that case, the result shall be +0
	 * even if the sign bit of x is 1. To handle this case properly,
	 * we do the swap is abs(x) = abs(y) AND the sign of x is 1.
	 */
	m = (1ULL << 63) - 1;
	za = (x & m) - (y & m);
	cs = (uint32_t)(za >> 63) | ((1U - (uint32_t)(-(int64_t)za >> 63)) & (uint32_t)(x >> 63));
	m = (x ^ y) & (uint64_t)-(int64_t)cs;
	x ^= m;
	y ^= m;

	/*
	 * Extract sign bits, exponents and mantissas. The mantissas are
	 * scaled up to 2^55..2^56-1, and the exponent is unbiased. If
	 * an operand is zero, its mantissa is set to 0 at this step, and
	 * its exponent will be -1078.
	 */
	ex = (int32_t)(x >> 52);
	sx = ex >> 11;
	ex &= 0x000007FFL;
	m = (uint64_t)(uint32_t)((ex + 0x000007FFL) >> 11) << 52;
	xu = ((x & ((1ULL << 52) - 1)) | m) << 3;
	ex -= 1078;
	ey = (int32_t)(y >> 52);
	sy = ey >> 11;
	ey &= 0x000007FFL;
	m = (uint64_t)(uint32_t)((ey + 0x000007FFL) >> 11) << 52;
	yu = ((y & ((1ULL << 52) - 1)) | m) << 3;
	ey -= 1078;

	/*
	 * x has the larger exponent; hence, we only need to right-shift y.
	 * If the shift count is larger than 59 bits then we clamp the
	 * value to zero.
	 */
	cc = ex - ey;
	yu &= (uint64_t)-(int64_t)((uint32_t)(cc - 60) >> 31);
	cc &= 63;

	/*
	 * The lowest bit of yu is "sticky".
	 */
	m = falcon_fpr_ulsh(1, cc) - 1;
	yu |= (yu & m) + m;
	yu = falcon_fpr_ursh(yu, cc);

	/*
	 * If the operands have the same sign, then we add the mantissas
	 * otherwise, we subtract the mantissas.
	 */
	xu += yu - ((yu << 1) & (uint64_t)-(int64_t)(sx ^ sy));

	/*
	 * The result may be smaller, or slightly larger. We normalize
	 * it to the 2^63..2^64-1 range (if xu is zero, then it stays
	 * at zero).
	 */
	falcon_fpr_norm64(&xu, &ex);

	/*
	 * Scale down the value to 2^54..s^55-1, handling the last bit
	 * as sticky.
	 */
	xu |= ((uint32_t)xu & 0x000001FFUL) + 0x000001FFUL;
	xu >>= 9;
	ex += 9;

	/*
	 * In general, the result has the sign of x. However, if the
	 * result is exactly zero, then the following situations may
	 * be encountered:
	 *   x > 0, y = -x   -> result should be +0
	 *   x < 0, y = -x   -> result should be +0
	 *   x = +0, y = +0  -> result should be +0
	 *   x = -0, y = +0  -> result should be +0
	 *   x = +0, y = -0  -> result should be +0
	 *   x = -0, y = -0  -> result should be -0
	 *
	 * But at the conditional swap step at the start of the
	 * function, we ensured that if abs(x) = abs(y) and the
	 * sign of x was 1, then x and y were swapped. Thus, the
	 * two following cases cannot actually happen:
	 *   x < 0, y = -x
	 *   x = -0, y = +0
	 * In all other cases, the sign bit of x is conserved, which
	 * is what the falcon_FPR() function does. The falcon_FPR() function also
	 * properly clamps values to zero when the exponent is too
	 * low, but does not alter the sign in that case.
	 */
	return falcon_FPR(sx, ex, xu);
}

 falcon_fpr falcon_fpr_mul(falcon_fpr x, falcon_fpr y)
{
	uint64_t xu;
	uint64_t yu;
	uint64_t w;
	uint64_t zu;
	uint64_t zv;
	uint64_t x1;
	uint64_t y0;
	uint64_t y1;
	uint64_t z0;
	uint64_t z1;
	uint64_t z2;
	uint32_t x0;
	int32_t ex;
	int32_t ey;
	int32_t d;
	int32_t e;
	int32_t s;

	/*
	 * Extract absolute values as scaled uint32_t integers. We
	 * don't extract exponents yet.
	 */
	xu = (x & ((1ULL << 52) - 1)) | (1ULL << 52);
	yu = (y & ((1ULL << 52) - 1)) | (1ULL << 52);

	/*
	 * We have two 53-bit integers to multiply; we need to split
	 * each into a lower half and a upper half. Moreover, we
	 * prefer to have lower halves to be of 25 bits each, for
	 * reasons explained later on.
	 */
	x0 = (uint32_t)xu & 0x01FFFFFFUL;
	x1 = (uint32_t)(xu >> 25);
	y0 = (uint32_t)yu & 0x01FFFFFFUL;
	y1 = (uint32_t)(yu >> 25);
	w = (uint64_t)x0 * y0;
	z0 = (uint32_t)w & 0x01FFFFFFUL;
	z1 = (uint32_t)(w >> 25);
	w = (uint64_t)x0 * y1;
	z1 += (uint32_t)w & 0x01FFFFFFUL;
	z2 = (uint32_t)(w >> 25);
	w = x1 * y0;
	z1 += (uint32_t)w & 0x01FFFFFFUL;
	z2 += (uint32_t)(w >> 25);
	zu = x1 * y1;
	z2 += (z1 >> 25);
	z1 &= 0x01FFFFFFUL;
	zu += z2;

	/*
	 * Since xu and yu are both in the 2^52..2^53-1 range, the
	 * product is in the 2^104..2^106-1 range. We first reassemble
	 * it and round it into the 2^54..2^56-1 range; the bottom bit
	 * is made "sticky". Since the low limbs z0 and z1 are 25 bits
	 * each, we just take the upper part (zu), and consider z0 and
	 * z1 only for purposes of stickiness.
	 * (This is the reason why we chose 25-bit limbs above.)
	 */
	zu |= ((z0 | z1) + 0x01FFFFFFUL) >> 25;

	/*
	 * We normalize zu to the 2^54..s^55-1 range: it could be one
	 * bit too large at this point. This is done with a conditional
	 * right-shift that takes into account the sticky bit.
	 */
	zv = (zu >> 1) | (zu & 1);
	w = zu >> 55;
	zu ^= (zu ^ zv) & (uint64_t)-(int64_t)w;

	/*
	 * Get the aggregate scaling factor:
	 *
	 *   - Each exponent is biased by 1023.
	 *
	 *   - Integral mantissas are scaled by 2^52, hence an
	 *     extra 52 bias for each exponent.
	 *
	 *   - However, we right-shifted z by 50 bits, and then
	 *     by 0 or 1 extra bit (depending on the value of w).
	 *
	 * In total, we must add the exponents, then subtract
	 * 2 * (1023 + 52), then add 50 + w.
	 */
	ex = (int32_t)((x >> 52) & 0x000007FFUL);
	ey = (int32_t)((y >> 52) & 0x000007FFUL);
	e = ex + ey - 2100 + (int32_t)w;

	/*
	 * Sign bit is the XOR of the operand sign bits.
	 */
	s = (int32_t)((x ^ y) >> 63);

	/*
	 * Corrective actions for zeros: if either of the operands is
	 * zero, then the computations above were wrong. Test for zero
	 * is whether ex or ey is zero. We just have to set the mantissa
	 * (zu) to zero, the falcon_FPR() function will normalize e.
	 */
	d = ((ex + 0x000007FFL) & (ey + 0x000007FFL)) >> 11;
	zu &= (uint64_t)-(int64_t)d;

	/*
	 * falcon_FPR() packs the result and applies proper rounding.
	 */
	return falcon_FPR(s, e, zu);
}

static falcon_fpr falcon_fpr_div(falcon_fpr x, falcon_fpr y)
{
	uint64_t xu;
	uint64_t yu;
	uint64_t q;
	uint64_t q2;
	uint64_t w;
	int32_t i;
	int32_t ex;
	int32_t ey;
	int32_t e;
	int32_t d;
	int32_t s;

	/*
	 * Extract mantissas of x and y (uint32_t).
	 */
	xu = (x & ((1ULL << 52) - 1)) | (1ULL << 52);
	yu = (y & ((1ULL << 52) - 1)) | (1ULL << 52);

	/*
	 * Perform bit-by-bit division of xu by yu. We run it for 55 bits.
	 */
	q = 0;

	for (i = 0; i < 55; ++i)
	{
		/*
		 * If yu is less than or equal xu, then subtract it and
		 * push a 1 in the quotient; otherwise, leave xu unchanged
		 * and push a 0.
		 */
		uint64_t b;

		b = ((xu - yu) >> 63) - 1;
		xu -= b & yu;
		q |= b & 1;
		xu <<= 1;
		q <<= 1;
	}

	/*
	 * We got 55 bits in the quotient, followed by an extra zero. We
	 * want that 56th bit to be "sticky": it should be a 1 if and
	 * only if the remainder (xu) is non-zero.
	 */
	q |= (xu | (uint64_t)-(int64_t)xu) >> 63;

	/*
	 * Quotient is at most 2^56-1. Its top bit may be zero, but in
	 * that case the next-to-top bit will be a one, since the
	 * initial xu and yu were both in the 2^52..2^53-1 range.
	 * We perform a conditional shift to normalize q to the
	 * 2^54..2^55-1 range (with the bottom bit being sticky).
	 */
	q2 = (q >> 1) | (q & 1);
	w = q >> 55;
	q ^= (q ^ q2) & (uint64_t)-(int64_t)w;

	/*
	 * Extract exponents to compute the scaling factor:
	 *
	 *   - Each exponent is biased and we scaled them up by
	 *     52 bits; but these biases will cancel out.
	 *
	 *   - The division loop produced a 55-bit shifted result,
	 *     so we must scale it down by 55 bits.
	 *
	 *   - If w = 1, we right-shifted the integer by 1 bit,
	 *     hence we must add 1 to the scaling.
	 */
	ex = (int32_t)((x >> 52) & 0x000007FFL);
	ey = (int32_t)((y >> 52) & 0x000007FFL);
	e = ex - ey - 55 + (int32_t)w;

	/*
	 * Sign is the XOR of the signs of the operands.
	 */
	s = (int32_t)((x ^ y) >> 63);

	/*
	 * Corrective actions for zeros: if x = 0, then the computation
	 * is wrong, and we must clamp e and q to 0. We do not care
	 * about the case y = 0 (as per assumptions in this module,
	 * the caller does not perform divisions by zero).
	 */
	d = (ex + 0x000007FFL) >> 11;
	s &= d;
	e &= -d;
	q &= (uint64_t)-(int64_t)d;

	/*
	 * falcon_FPR() packs the result and applies proper rounding.
	 */
	return falcon_FPR(s, e, q);
}

static falcon_fpr falcon_fpr_inv(falcon_fpr x)
{
	return falcon_fpr_div(4607182418800017408ULL, x);
}

static falcon_fpr falcon_fpr_sqr(falcon_fpr x)
{
	return falcon_fpr_mul(x, x);
}

static falcon_fpr falcon_fpr_sqrt(falcon_fpr x)
{
	uint64_t xu;
	uint64_t q;
	uint64_t s;
	uint64_t r;
	int32_t ex;
	int32_t e;

	/*
	 * Extract the mantissa and the exponent. We don't care about
	 * the sign: by assumption, the operand is nonnegative.
	 * We want the "true" exponent corresponding to a mantissa
	 * in the 1..2 range.
	 */
	xu = (x & ((1ULL << 52) - 1)) | (1ULL << 52);
	ex = (int32_t)((x >> 52) & 0x000007FFL);
	e = ex - 1023;

	/*
	 * If the exponent is odd, double the mantissa and decrement
	 * the exponent. The exponent is then halved to account for
	 * the square root.
	 */
	xu += xu & (uint64_t)-(int64_t)(e & 1);
	e >>= 1;

	/*
	 * Double the mantissa.
	 */
	xu <<= 1;

	/*
	 * We now have a mantissa in the 2^53..2^55-1 range. It
	 * represents a value between 1 (inclusive) and 4 (exclusive)
	 * in fixed point notation (with 53 fractional bits). We
	 * compute the square root bit by bit.
	 */
	q = 0;
	s = 0;
	r = 1ULL << 53;

	for (int32_t i = 0; i < 54; ++i)
	{
		uint64_t b;
		uint64_t t;

		t = s + r;
		b = ((xu - t) >> 63) - 1;
		s += (r << 1) & b;
		xu -= t & b;
		q += r & b;
		xu <<= 1;
		r >>= 1;
	}

	/*
	 * Now, q is a rounded-low 54-bit value, with a leading 1,
	 * 52 fractional digits, and an additional guard bit. We add
	 * an extra sticky bit to account for what remains of the operand.
	 */
	q <<= 1;
	q |= (xu | (uint64_t)-(int64_t)xu) >> 63;

	/*
	 * Result q is in the 2^54..2^55-1 range; we bias the exponent
	 * by 54 bits (the value e at that point contains the "true"
	 * exponent, but q is now considered an integer, i.e. scaled
	 * up.
	 */
	e -= 54;

	/*
	 * Corrective action for an operand of value zero.
	 */
	q &= (uint64_t)-(int64_t)((ex + 0x000007FFL) >> 11);

	/*
	 * Apply rounding and back result.
	 */
	return falcon_FPR(0, e, q);
}

static falcon_fpr falcon_fpr_sub(falcon_fpr x, falcon_fpr y)
{
	y ^= 1ULL << 63;

	return falcon_fpr_add(x, y);
}

static uint64_t falcon_fpr_expm_p63(falcon_fpr x, falcon_fpr ccs)
{
	/*
	* Polynomial approximation of exp(-x) is taken from FACCT:
	*   https://eprint.iacr.org/2018/1234
	* Specifically, values are extracted from the implementation
	* referenced from the FACCT article, and available at:
	*   https://github.com/raykzhao/gaussian
	* Here, the coefficients have been scaled up by 2^63 and
	* converted to integers.
	*
	* Tests over more than 24 billions of random inputs in the
	* 0..log(2) range have never shown a deviation larger than
	* 2^(-50) from the true mathematical value.
	*/
	static const uint64_t C[] =
	{
		0X00000004741183A3ULL, 0X00000036548CFC06ULL, 0X0000024FDCBF140AULL, 0X0000171D939DE045ULL,
		0X0000D00CF58F6F84ULL, 0X000680681CF796E3ULL, 0X002D82D8305B0FEAULL, 0X011111110E066FD0ULL,
		0X0555555555070F00ULL, 0X155555555581FF00ULL, 0X400000000002B400ULL, 0X7FFFFFFFFFFF4800ULL,
		0X8000000000000000ULL
	};

	uint64_t a;
	uint64_t b;
	uint64_t y;
	uint64_t z;
	uint32_t u;
	uint32_t z0;
	uint32_t z1;
	uint32_t y0;
	uint32_t y1;

	y = C[0];
	z = (uint64_t)falcon_fpr_trunc(falcon_fpr_mul(x, falcon_fpr_ptwo63)) << 1;

	for (u = 1; u < (sizeof(C) / sizeof(C[0])); ++u)
	{
		/*
		 * Compute product z * y over 128 bits, but keep only the top 64 bits.
		 *
		 * TODO: On some architectures/compilers we could use
		 * some intrinsics (__umulh() on MSVC) or other compiler
		 * extensions (uint32_t __int128 on GCC / Clang) for
		 * improved speed; however, most 64-bit architectures
		 * also have appropriate IEEE754 floating-point support,
		 * which is better.
		 */
		uint64_t c;

		z0 = (uint32_t)z;
		z1 = (uint32_t)(z >> 32);
		y0 = (uint32_t)y;
		y1 = (uint32_t)(y >> 32);
		a = ((uint64_t)z0 * (uint64_t)y1) + (((uint64_t)z0 * (uint64_t)y0) >> 32);
		b = ((uint64_t)z1 * (uint64_t)y0);
		c = (a >> 32) + (b >> 32);
		c += (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32);
		c += (uint64_t)z1 * (uint64_t)y1;
		y = C[u] - c;
	}

	/*
	 * The scaling factor must be applied at the end. Since y is now
	 * in fixed-point notation, we have to convert the factor to the
	 * same format, and do an extra integer multiplication.
	 */
	z = (uint64_t)falcon_fpr_trunc(falcon_fpr_mul(ccs, falcon_fpr_ptwo63)) << 1;
	z0 = (uint32_t)z;
	z1 = (uint32_t)(z >> 32);
	y0 = (uint32_t)y;
	y1 = (uint32_t)(y >> 32);
	a = ((uint64_t)z0 * (uint64_t)y1) + (((uint64_t)z0 * (uint64_t)y0) >> 32);
	b = ((uint64_t)z1 * (uint64_t)y0);
	y = (a >> 32) + (b >> 32);
	y += (((uint64_t)(uint32_t)a + (uint64_t)(uint32_t)b) >> 32);
	y += (uint64_t)z1 * (uint64_t)y1;

	return y;
}

/* prng */

inline static void falcon_chacha_round(uint32_t state[16], size_t a, size_t b, size_t c, size_t d)
{
	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = (state[d] << 16) | (state[d] >> 16);
	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = (state[b] << 12) | (state[b] >> 20);
	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = (state[d] << 8) | (state[d] >> 24);
	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = (state[b] << 7) | (state[b] >> 25);
}

static void falcon_prng_refill(falcon_prng_state* pctx)
{
	/*
	* PRNG based on ChaCha20.
	*
	* State consists in key (32 bytes) then IV (16 bytes) and block counter
	* (8 bytes). Normally, we should not care about local endianness (this
	* is for a PRNG), but for the NIST competition we need reproducible KAT
	* vectors that work across architectures, so we enforce little-endian
	* interpretation where applicable. Moreover, output words are "spread
	* out" over the output buffer with the interleaving pattern that is
	* naturally obtained from the AVX2 implementation that runs eight
	* ChaCha20 instances in parallel.
	*
	* The block counter is XORed into the first 8 bytes of the IV.
	*/

	static const uint32_t CW[] = { 0x61707865UL, 0x3320646EUL, 0x79622D32UL, 0x6B206574UL };
	uint64_t cc;
	size_t u;

	/*
	 * State uses local endianness. Only the output bytes must be
	 * converted to little endian (if used on a big-endian machine).
	 */
	cc = *(uint64_t*)(pctx->state + 48);

	for (u = 0; u < 8; ++u)
	{
		uint32_t state[16] = { 0 };
		size_t v;
		int32_t i;

		qsc_memutils_copy(&state[0], CW, sizeof(CW));
		qsc_memutils_copy(&state[4], pctx->state, 48);
		state[14] ^= (uint32_t)cc;
		state[15] ^= (uint32_t)(cc >> 32);

		for (i = 0; i < 10; ++i)
		{
			falcon_chacha_round(state, 0, 4, 8, 12);
			falcon_chacha_round(state, 1, 5, 9, 13);
			falcon_chacha_round(state, 2, 6, 10, 14);
			falcon_chacha_round(state, 3, 7, 11, 15);
			falcon_chacha_round(state, 0, 5, 10, 15);
			falcon_chacha_round(state, 1, 6, 11, 12);
			falcon_chacha_round(state, 2, 7, 8, 13);
			falcon_chacha_round(state, 3, 4, 9, 14);
		}

		for (v = 0; v < 4; ++v)
		{
			state[v] += CW[v];
		}

		for (v = 4; v < 14; ++v)
		{
			state[v] += ((uint32_t *)pctx->state)[v - 4];
		}

		state[14] += ((uint32_t*)pctx->state)[10] ^ (uint32_t)cc;
		state[15] += ((uint32_t*)pctx->state)[11] ^ (uint32_t)(cc >> 32);
		cc++;

		/*
		 * We mimic the interleaving that is used in the AVX2
		 * implementation.
		 */
		for (v = 0; v < 16; ++v)
		{
			pctx->buf[(u << 2) + (v << 5)] = (uint8_t)state[v];
			pctx->buf[(u << 2) + (v << 5) + 1] = (uint8_t)(state[v] >> 8);
			pctx->buf[(u << 2) + (v << 5) + 2] = (uint8_t)(state[v] >> 16);
			pctx->buf[(u << 2) + (v << 5) + 3] = (uint8_t)(state[v] >> 24);
		}
	}

	*(uint64_t*)(pctx->state + 48) = cc;
	pctx->ptr = 0;
}

static void falcon_prng_init(falcon_prng_state* pctx, qsc_keccak_state* kctx)
{
	/*
	 * To ensure reproducibility for a given seed, we
	 * must enforce little-endian interpretation of
	 * the state words.
	 */
	uint8_t tmp[56];
	uint64_t th;
	uint64_t tl;

	qsc_keccak_incremental_squeeze(kctx, QSC_KECCAK_256_RATE, tmp, 56);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(pctx->state, tmp, 14 * sizeof(uint32_t));
#else
	for (size_t i = 0; i < 14; i++)
	{
		uint32_t w;

		w = (uint32_t)tmp[(i << 2)]
			| ((uint32_t)tmp[(i << 2) + 1] << 8)
			| ((uint32_t)tmp[(i << 2) + 2] << 16)
			| ((uint32_t)tmp[(i << 2) + 3] << 24);

		*(uint32_t*)(pctx->state + (i << 2)) = w;
	}
#endif

	tl = *(uint32_t*)(pctx->state + 48);
	th = *(uint32_t*)(pctx->state + 52);
	*(uint64_t*)(pctx->state + 48) = tl + (th << 32);
	falcon_prng_refill(pctx);
}

static uint64_t falcon_prng_get_u64(falcon_prng_state* pctx)
{
	size_t u;

	/*
	 * If there are less than 9 bytes in the buffer, we refill it.
	 * This means that we may drop the last few bytes, but this allows
	 * for faster extraction code. Also, it means that we never leave
	 * an empty buffer.
	 */
	u = pctx->ptr;

	if (u >= sizeof(pctx->buf) - 9)
	{
		falcon_prng_refill(pctx);
		u = 0;
	}

	pctx->ptr = u + 8;

	/*
	 * On systems that use little-endian encoding and allow
	 * unaligned accesses, we can simply read the data where it is.
	 */
	return (uint64_t)pctx->buf[u]
		| ((uint64_t)pctx->buf[u + 1] << 8)
		| ((uint64_t)pctx->buf[u + 2] << 16)
		| ((uint64_t)pctx->buf[u + 3] << 24)
		| ((uint64_t)pctx->buf[u + 4] << 32)
		| ((uint64_t)pctx->buf[u + 5] << 40)
		| ((uint64_t)pctx->buf[u + 6] << 48)
		| ((uint64_t)pctx->buf[u + 7] << 56);
}

static uint32_t falcon_prng_get_u8(falcon_prng_state* pctx)
{
	uint32_t v;

	v = pctx->buf[pctx->ptr];
	++pctx->ptr;

	if (pctx->ptr == sizeof(pctx->buf))
	{
		falcon_prng_refill(pctx);
	}

	return v;
}

/* codec.c */

const uint8_t falcon_max_fg_bits[FALCON_MAXBITS_SIZE] =
{
	0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x07, 0x07, 0x06, 0x06, 0x05
};

const uint8_t falcon_max_FG_bits[FALCON_MAXBITS_SIZE] =
{
	0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
};

static size_t falcon_modq_encode(void* out, size_t maxoutlen, const uint16_t* x, uint32_t logn)
{
	size_t n;
	size_t outlen;
	size_t u;
	uint32_t acc;
	int32_t acclen;
	uint8_t* buf;
	bool res;

	res = true;
	outlen = 0;
	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		if (x[u] >= 12289)
		{
			res = false;
			break;
		}
	}

	if (res == true)
	{
		outlen = ((n * 14) + 7) >> 3;

		if (out != NULL && outlen <= maxoutlen)
		{

			buf = out;
			acc = 0;
			acclen = 0;

			for (u = 0; u < n; ++u)
			{
				acc = (acc << 14) | x[u];
				acclen += 14;

				while (acclen >= 8)
				{
					acclen -= 8;
					*buf++ = (uint8_t)(acc >> acclen);
				}
			}

			if (acclen > 0)
			{
				*buf = (uint8_t)(acc << (8 - acclen));
			}
		}
	}

	return outlen;
}

static size_t falcon_modq_decode(uint16_t* x, uint32_t logn, const void* in, size_t maxinlen)
{
	size_t n;
	size_t inlen;
	size_t u;
	uint32_t acc;
	int32_t acclen;
	const uint8_t *buf;

	n = (size_t)1 << logn;
	inlen = ((n * 14) + 7) >> 3;

	if (inlen > maxinlen)
	{
		inlen = 0;
	}

	if (inlen > 0)
	{
		buf = in;
		acc = 0;
		acclen = 0;
		u = 0;

		while (u < n)
		{
			acc = (acc << 8) | (*buf++);
			acclen += 8;

			if (acclen >= 14)
			{
				uint32_t w;

				acclen -= 14;
				w = (acc >> acclen) & 0x00003FFFUL;

				if (w >= 12289)
				{
					inlen = 0;
					break;
				}

				x[u] = (uint16_t)w;
				++u;
			}
		}

		if ((acc & ((1UL << acclen) - 1)) != 0)
		{
			inlen = 0;
		}
	}

	return inlen;
}

static size_t falcon_trim_i8_encode(void* out, size_t maxoutlen, const int8_t* x, uint32_t logn, uint32_t bits)
{
	size_t outlen;
	size_t n;
	size_t u;
	uint32_t acc;
	uint32_t mask;
	uint32_t acclen;
	int32_t minv;
	int32_t maxv;
	uint8_t* buf;

	n = (size_t)1 << logn;
	maxv = (1 << (bits - 1)) - 1;
	minv = -maxv;

	for (u = 0; u < n; ++u)
	{
		if (x[u] < minv || x[u] > maxv)
		{
			return 0;
		}
	}

	outlen = ((n * bits) + 7) >> 3;

	if (out == NULL)
	{
		return outlen;
	}

	if (outlen > maxoutlen)
	{
		return 0;
	}

	buf = out;
	acc = 0;
	acclen = 0;
	mask = (1UL << bits) - 1;

	for (u = 0; u < n; ++u)
	{
		acc = (acc << bits) | ((uint8_t)x[u] & mask);
		acclen += bits;

		while (acclen >= 8)
		{
			acclen -= 8;
			*buf++ = (uint8_t)(acc >> acclen);
		}
	}

	if (acclen > 0)
	{
		*buf++ = (uint8_t)(acc << (8 - acclen));
	}

	return outlen;
}

static size_t falcon_trim_i8_decode(int8_t* x, uint32_t logn, uint32_t bits, const void* in, size_t maxinlen)
{
	size_t inlen;
	size_t n;
	size_t u;
	uint32_t acc;
	uint32_t acclen;
	uint32_t mask1;
	uint32_t mask2;
	const uint8_t *buf;

	n = (size_t)1 << logn;
	inlen = ((n * bits) + 7) >> 3;

	if (inlen > maxinlen)
	{
		return 0;
	}

	buf = in;
	u = 0;
	acc = 0;
	acclen = 0;
	mask1 = (1UL << bits) - 1;
	mask2 = 1UL << (bits - 1);

	while (u < n)
	{
		acc = (acc << 8) | *buf++;
		acclen += 8;

		while (acclen >= bits && u < n)
		{
			uint32_t w;

			acclen -= bits;
			w = (acc >> acclen) & mask1;
			w |= (uint32_t)-(int32_t)(w & mask2);

			if (w == (uint32_t)-(int32_t)mask2)
			{
				/*
				 * The -2^(bits-1) value is forbidden.
				 */
				return 0;
			}

			x[u] = (int8_t) * (int32_t*)&w;
			++u;
		}
	}

	if ((acc & ((1UL << acclen) - 1)) != 0)
	{
		/*
		 * Extra bits in the last byte must be zero.
		 */
		return 0;
	}

	return inlen;
}

static size_t falcon_comp_encode(void* out, size_t maxoutlen, const int16_t* x, uint32_t logn)
{
	uint8_t *buf;
	size_t n;
	size_t u;
	size_t v;
	uint32_t acc;
	uint32_t acclen;

	n = (size_t)1 << logn;
	buf = out;

	/*
	 * Make sure that all values are within the -2047..+2047 range.
	 */
	for (u = 0; u < n; ++u)
	{
		if (x[u] < -2047 || x[u] > +2047)
		{
			return 0;
		}
	}

	acc = 0;
	acclen = 0;
	v = 0;

	for (u = 0; u < n; ++u)
	{
		int32_t t;
		uint32_t w;

		/*
		 * Get sign and absolute value of next integer; push the
		 * sign bit.
		 */
		acc <<= 1;
		t = x[u];

		if (t < 0)
		{
			t = -t;
			acc |= 1;
		}

		w = (uint32_t)t;

		/*
		 * Push the low 7 bits of the absolute value.
		 */
		acc <<= 7;
		acc |= w & 127u;
		w >>= 7;

		/*
		 * We pushed exactly 8 bits.
		 */
		acclen += 8;

		/*
		 * Push as many zeros as necessary, then a one. Since the
		 * absolute value is at most 2047, w can only range up to
		 * 15 at this point, thus we will add at most 16 bits
		 * here. With the 8 bits above and possibly up to 7 bits
		 * from previous iterations, we may go up to 31 bits, which
		 * will fit in the accumulator, which is an uint32_t.
		 */
		acc <<= (w + 1);
		acc |= 1;
		acclen += w + 1;

		/*
		 * Produce all full bytes.
		 */
		while (acclen >= 8)
		{
			acclen -= 8;

			if (buf != NULL)
			{
				if (v >= maxoutlen)
				{
					return 0;
				}

				buf[v] = (uint8_t)(acc >> acclen);
			}

			++v;
		}
	}

	/*
	 * Flush remaining bits (if any).
	 */
	if (acclen > 0)
	{
		if (buf != NULL)
		{
			if (v >= maxoutlen)
			{
				return 0;
			}

			buf[v] = (uint8_t)(acc << (8 - acclen));
		}

		++v;
	}

	return v;
}

static size_t falcon_comp_decode(int16_t* x, uint32_t logn, const void* in, size_t maxinlen)
{
	const uint8_t *buf;
	size_t n;
	size_t u;
	size_t v;
	uint32_t acc;
	uint32_t acclen;

	n = (size_t)1 << logn;
	buf = in;
	acc = 0;
	acclen = 0;
	v = 0;

	for (u = 0; u < n; ++u)
	{
		uint32_t b;
		uint32_t s;
		uint32_t m;

		/*
		 * Get next eight bits: sign and low seven bits of the
		 * absolute value.
		 */
		if (v >= maxinlen)
		{
			return 0;
		}

		acc = (acc << 8) | (uint32_t)buf[v];
		++v;
		b = acc >> acclen;
		s = b & 128;
		m = b & 127;

		/*
		 * Get next bits until a 1 is reached.
		 */
		for (;;)
		{
			if (acclen == 0)
			{
				if (v >= maxinlen)
				{
					return 0;
				}

				acc = (acc << 8) | (uint32_t)buf[v];
				++v;
				acclen = 8;
			}

			--acclen;

			if (((acc >> acclen) & 1) != 0)
			{
				break;
			}

			m += 128;

			if (m > 2047)
			{
				return 0;
			}
		}

		/*
		 * "-0" is forbidden.
		 */
		if (s && m == 0)
		{
			return 0;
		}

		x[u] = (int16_t)(s ? -(int32_t)m : (int32_t)m);
	}

	/*
	 * Unused bits in the last byte must be zero.
	 */
	if ((acc & ((1u << acclen) - 1u)) != 0)
	{
		return 0;
	}

	return v;
}

/* common.c */

const uint32_t falcon_l2bound[FALCON_L2BOUND_SIZE] =
{
	0x00000000UL, 0x00018C7AUL, 0x00032F4AUL, 0x00068B41UL,
	0x000D9C87UL, 0x001C4518UL, 0x003AA246UL, 0x007974B6UL,
	0x00FB49C0UL, 0x02075426UL, 0x0430299AUL
};

static void falcon_hash_to_point_vartime(qsc_keccak_state* kctx, uint16_t* x, uint32_t logn)
{
	size_t n;

	n = (size_t)1 << logn;

	while (n > 0)
	{
		uint8_t buf[2];
		uint32_t w;

		qsc_keccak_incremental_squeeze(kctx, QSC_KECCAK_256_RATE, buf, sizeof(buf));
		w = ((uint32_t)buf[0] << 8) | (uint32_t)buf[1];

		if (w < 61445)
		{
			while (w >= 12289)
			{
				w -= 12289;
			}

			*x = (uint16_t)w;
			x++;
			n--;
		}
	}
}

static int32_t falcon_is_short(const int16_t* s1, const int16_t* s2, uint32_t logn)
{
	/*
	 * We use the l2-norm. Code below uses only 32-bit operations to
	 * compute the square of the norm with saturation to 2^32-1 if
	 * the value exceeds 2^31-1.
	 */
	size_t n;
	size_t u;
	uint32_t ng;
	uint32_t s;

	n = (size_t)1 << logn;
	s = 0;
	ng = 0;

	for (u = 0; u < n; ++u)
	{
		int32_t z;

		z = s1[u];
		s += (uint32_t)(z * z);
		ng |= s;
		z = s2[u];
		s += (uint32_t)(z * z);
		ng |= s;
	}

	s |= (uint32_t)-(int32_t)(ng >> 31);

	return s <= falcon_l2bound[logn];
}

static int32_t falcon_is_short_half(uint32_t sqn, const int16_t* s2, uint32_t logn)
{
	size_t n;
	size_t u;
	uint32_t ng;

	n = (size_t)1 << logn;
	ng = (uint32_t)-(int32_t)(sqn >> 31);

	for (u = 0; u < n; ++u)
	{
		int32_t z;

		z = s2[u];
		sqn += (uint32_t)(z * z);
		ng |= sqn;
	}

	sqn |= (uint32_t)-(int32_t)(ng >> 31);

	return sqn <= falcon_l2bound[logn];
}

/* falcon_fpr.c */

const falcon_fpr falcon_fpr_gm_tab[FALCON_FPR_GM_TAB_SIZE] =
{
	0x0000000000000000ULL, 0x0000000000000000ULL, 0x8000000000000000ULL, 0x3FF0000000000000ULL,
	0x3FE6A09E667F3BCDULL, 0x3FE6A09E667F3BCDULL, 0xBFE6A09E667F3BCDULL, 0x3FE6A09E667F3BCDULL,
	0x3FED906BCF328D46ULL, 0x3FD87DE2A6AEA963ULL, 0xBFD87DE2A6AEA963ULL, 0x3FED906BCF328D46ULL,
	0x3FD87DE2A6AEA963ULL, 0x3FED906BCF328D46ULL, 0xBFED906BCF328D46ULL, 0x3FD87DE2A6AEA963ULL,
	0x3FEF6297CFF75CB0ULL, 0x3FC8F8B83C69A60BULL, 0xBFC8F8B83C69A60BULL, 0x3FEF6297CFF75CB0ULL,
	0x3FE1C73B39AE68C8ULL, 0x3FEA9B66290EA1A3ULL, 0xBFEA9B66290EA1A3ULL, 0x3FE1C73B39AE68C8ULL,
	0x3FEA9B66290EA1A3ULL, 0x3FE1C73B39AE68C8ULL, 0xBFE1C73B39AE68C8ULL, 0x3FEA9B66290EA1A3ULL,
	0x3FC8F8B83C69A60BULL, 0x3FEF6297CFF75CB0ULL, 0xBFEF6297CFF75CB0ULL, 0x3FC8F8B83C69A60BULL,
	0x3FEFD88DA3D12526ULL, 0x3FB917A6BC29B42CULL, 0xBFB917A6BC29B42CULL, 0x3FEFD88DA3D12526ULL,
	0x3FE44CF325091DD6ULL, 0x3FE8BC806B151741ULL, 0xBFE8BC806B151741ULL, 0x3FE44CF325091DD6ULL,
	0x3FEC38B2F180BDB1ULL, 0x3FDE2B5D3806F63BULL, 0xBFDE2B5D3806F63BULL, 0x3FEC38B2F180BDB1ULL,
	0x3FD294062ED59F06ULL, 0x3FEE9F4156C62DDAULL, 0xBFEE9F4156C62DDAULL, 0x3FD294062ED59F06ULL,
	0x3FEE9F4156C62DDAULL, 0x3FD294062ED59F06ULL, 0xBFD294062ED59F06ULL, 0x3FEE9F4156C62DDAULL,
	0x3FDE2B5D3806F63BULL, 0x3FEC38B2F180BDB1ULL, 0xBFEC38B2F180BDB1ULL, 0x3FDE2B5D3806F63BULL,
	0x3FE8BC806B151741ULL, 0x3FE44CF325091DD6ULL, 0xBFE44CF325091DD6ULL, 0x3FE8BC806B151741ULL,
	0x3FB917A6BC29B42CULL, 0x3FEFD88DA3D12526ULL, 0xBFEFD88DA3D12526ULL, 0x3FB917A6BC29B42CULL,
	0x3FEFF621E3796D7EULL, 0x3FA91F65F10DD814ULL, 0xBFA91F65F10DD814ULL, 0x3FEFF621E3796D7EULL,
	0x3FE57D69348CECA0ULL, 0x3FE7B5DF226AAFAFULL, 0xBFE7B5DF226AAFAFULL, 0x3FE57D69348CECA0ULL,
	0x3FECED7AF43CC773ULL, 0x3FDB5D1009E15CC0ULL, 0xBFDB5D1009E15CC0ULL, 0x3FECED7AF43CC773ULL,
	0x3FD58F9A75AB1FDDULL, 0x3FEE212104F686E5ULL, 0xBFEE212104F686E5ULL, 0x3FD58F9A75AB1FDDULL,
	0x3FEF0A7EFB9230D7ULL, 0x3FCF19F97B215F1BULL, 0xBFCF19F97B215F1BULL, 0x3FEF0A7EFB9230D7ULL,
	0x3FE073879922FFEEULL, 0x3FEB728345196E3EULL, 0xBFEB728345196E3EULL, 0x3FE073879922FFEEULL,
	0x3FE9B3E047F38741ULL, 0x3FE30FF7FCE17035ULL, 0xBFE30FF7FCE17035ULL, 0x3FE9B3E047F38741ULL,
	0x3FC2C8106E8E613AULL, 0x3FEFA7557F08A517ULL, 0xBFEFA7557F08A517ULL, 0x3FC2C8106E8E613AULL,
	0x3FEFA7557F08A517ULL, 0x3FC2C8106E8E613AULL, 0xBFC2C8106E8E613AULL, 0x3FEFA7557F08A517ULL,
	0x3FE30FF7FCE17035ULL, 0x3FE9B3E047F38741ULL, 0xBFE9B3E047F38741ULL, 0x3FE30FF7FCE17035ULL,
	0x3FEB728345196E3EULL, 0x3FE073879922FFEEULL, 0xBFE073879922FFEEULL, 0x3FEB728345196E3EULL,
	0x3FCF19F97B215F1BULL, 0x3FEF0A7EFB9230D7ULL, 0xBFEF0A7EFB9230D7ULL, 0x3FCF19F97B215F1BULL,
	0x3FEE212104F686E5ULL, 0x3FD58F9A75AB1FDDULL, 0xBFD58F9A75AB1FDDULL, 0x3FEE212104F686E5ULL,
	0x3FDB5D1009E15CC0ULL, 0x3FECED7AF43CC773ULL, 0xBFECED7AF43CC773ULL, 0x3FDB5D1009E15CC0ULL,
	0x3FE7B5DF226AAFAFULL, 0x3FE57D69348CECA0ULL, 0xBFE57D69348CECA0ULL, 0x3FE7B5DF226AAFAFULL,
	0x3FA91F65F10DD814ULL, 0x3FEFF621E3796D7EULL, 0xBFEFF621E3796D7EULL, 0x3FA91F65F10DD814ULL,
	0x3FEFFD886084CD0DULL, 0x3F992155F7A3667EULL, 0xBF992155F7A3667EULL, 0x3FEFFD886084CD0DULL,
	0x3FE610B7551D2CDFULL, 0x3FE72D0837EFFF96ULL, 0xBFE72D0837EFFF96ULL, 0x3FE610B7551D2CDFULL,
	0x3FED4134D14DC93AULL, 0x3FD9EF7943A8ED8AULL, 0xBFD9EF7943A8ED8AULL, 0x3FED4134D14DC93AULL,
	0x3FD7088530FA459FULL, 0x3FEDDB13B6CCC23CULL, 0xBFEDDB13B6CCC23CULL, 0x3FD7088530FA459FULL,
	0x3FEF38F3AC64E589ULL, 0x3FCC0B826A7E4F63ULL, 0xBFCC0B826A7E4F63ULL, 0x3FEF38F3AC64E589ULL,
	0x3FE11EB3541B4B23ULL, 0x3FEB090A58150200ULL, 0xBFEB090A58150200ULL, 0x3FE11EB3541B4B23ULL,
	0x3FEA29A7A0462782ULL, 0x3FE26D054CDD12DFULL, 0xBFE26D054CDD12DFULL, 0x3FEA29A7A0462782ULL,
	0x3FC5E214448B3FC6ULL, 0x3FEF8764FA714BA9ULL, 0xBFEF8764FA714BA9ULL, 0x3FC5E214448B3FC6ULL,
	0x3FEFC26470E19FD3ULL, 0x3FBF564E56A9730EULL, 0xBFBF564E56A9730EULL, 0x3FEFC26470E19FD3ULL,
	0x3FE3AFFA292050B9ULL, 0x3FE93A22499263FBULL, 0xBFE93A22499263FBULL, 0x3FE3AFFA292050B9ULL,
	0x3FEBD7C0AC6F952AULL, 0x3FDF8BA4DBF89ABAULL, 0xBFDF8BA4DBF89ABAULL, 0x3FEBD7C0AC6F952AULL,
	0x3FD111D262B1F677ULL, 0x3FEED740E7684963ULL, 0xBFEED740E7684963ULL, 0x3FD111D262B1F677ULL,
	0x3FEE6288EC48E112ULL, 0x3FD4135C94176601ULL, 0xBFD4135C94176601ULL, 0x3FEE6288EC48E112ULL,
	0x3FDCC66E9931C45EULL, 0x3FEC954B213411F5ULL, 0xBFEC954B213411F5ULL, 0x3FDCC66E9931C45EULL,
	0x3FE83B0E0BFF976EULL, 0x3FE4E6CABBE3E5E9ULL, 0xBFE4E6CABBE3E5E9ULL, 0x3FE83B0E0BFF976EULL,
	0x3FB2D52092CE19F6ULL, 0x3FEFE9CDAD01883AULL, 0xBFEFE9CDAD01883AULL, 0x3FB2D52092CE19F6ULL,
	0x3FEFE9CDAD01883AULL, 0x3FB2D52092CE19F6ULL, 0xBFB2D52092CE19F6ULL, 0x3FEFE9CDAD01883AULL,
	0x3FE4E6CABBE3E5E9ULL, 0x3FE83B0E0BFF976EULL, 0xBFE83B0E0BFF976EULL, 0x3FE4E6CABBE3E5E9ULL,
	0x3FEC954B213411F5ULL, 0x3FDCC66E9931C45EULL, 0xBFDCC66E9931C45EULL, 0x3FEC954B213411F5ULL,
	0x3FD4135C94176601ULL, 0x3FEE6288EC48E112ULL, 0xBFEE6288EC48E112ULL, 0x3FD4135C94176601ULL,
	0x3FEED740E7684963ULL, 0x3FD111D262B1F677ULL, 0xBFD111D262B1F677ULL, 0x3FEED740E7684963ULL,
	0x3FDF8BA4DBF89ABAULL, 0x3FEBD7C0AC6F952AULL, 0xBFEBD7C0AC6F952AULL, 0x3FDF8BA4DBF89ABAULL,
	0x3FE93A22499263FBULL, 0x3FE3AFFA292050B9ULL, 0xBFE3AFFA292050B9ULL, 0x3FE93A22499263FBULL,
	0x3FBF564E56A9730EULL, 0x3FEFC26470E19FD3ULL, 0xBFEFC26470E19FD3ULL, 0x3FBF564E56A9730EULL,
	0x3FEF8764FA714BA9ULL, 0x3FC5E214448B3FC6ULL, 0xBFC5E214448B3FC6ULL, 0x3FEF8764FA714BA9ULL,
	0x3FE26D054CDD12DFULL, 0x3FEA29A7A0462782ULL, 0xBFEA29A7A0462782ULL, 0x3FE26D054CDD12DFULL,
	0x3FEB090A58150200ULL, 0x3FE11EB3541B4B23ULL, 0xBFE11EB3541B4B23ULL, 0x3FEB090A58150200ULL,
	0x3FCC0B826A7E4F63ULL, 0x3FEF38F3AC64E589ULL, 0xBFEF38F3AC64E589ULL, 0x3FCC0B826A7E4F63ULL,
	0x3FEDDB13B6CCC23CULL, 0x3FD7088530FA459FULL, 0xBFD7088530FA459FULL, 0x3FEDDB13B6CCC23CULL,
	0x3FD9EF7943A8ED8AULL, 0x3FED4134D14DC93AULL, 0xBFED4134D14DC93AULL, 0x3FD9EF7943A8ED8AULL,
	0x3FE72D0837EFFF96ULL, 0x3FE610B7551D2CDFULL, 0xBFE610B7551D2CDFULL, 0x3FE72D0837EFFF96ULL,
	0x3F992155F7A3667EULL, 0x3FEFFD886084CD0DULL, 0xBFEFFD886084CD0DULL, 0x3F992155F7A3667EULL,
	0x3FEFFF62169B92DBULL, 0x3F8921D1FCDEC784ULL, 0xBF8921D1FCDEC784ULL, 0x3FEFFF62169B92DBULL,
	0x3FE6591925F0783DULL, 0x3FE6E74454EAA8AFULL, 0xBFE6E74454EAA8AFULL, 0x3FE6591925F0783DULL,
	0x3FED696173C9E68BULL, 0x3FD9372A63BC93D7ULL, 0xBFD9372A63BC93D7ULL, 0x3FED696173C9E68BULL,
	0x3FD7C3A9311DCCE7ULL, 0x3FEDB6526238A09BULL, 0xBFEDB6526238A09BULL, 0x3FD7C3A9311DCCE7ULL,
	0x3FEF4E603B0B2F2DULL, 0x3FCA82A025B00451ULL, 0xBFCA82A025B00451ULL, 0x3FEF4E603B0B2F2DULL,
	0x3FE1734D63DEDB49ULL, 0x3FEAD2BC9E21D511ULL, 0xBFEAD2BC9E21D511ULL, 0x3FE1734D63DEDB49ULL,
	0x3FEA63091B02FAE2ULL, 0x3FE21A799933EB59ULL, 0xBFE21A799933EB59ULL, 0x3FEA63091B02FAE2ULL,
	0x3FC76DD9DE50BF31ULL, 0x3FEF7599A3A12077ULL, 0xBFEF7599A3A12077ULL, 0x3FC76DD9DE50BF31ULL,
	0x3FEFCE15FD6DA67BULL, 0x3FBC3785C79EC2D5ULL, 0xBFBC3785C79EC2D5ULL, 0x3FEFCE15FD6DA67BULL,
	0x3FE3FED9534556D4ULL, 0x3FE8FBCCA3EF940DULL, 0xBFE8FBCCA3EF940DULL, 0x3FE3FED9534556D4ULL,
	0x3FEC08C426725549ULL, 0x3FDEDC1952EF78D6ULL, 0xBFDEDC1952EF78D6ULL, 0x3FEC08C426725549ULL,
	0x3FD1D3443F4CDB3EULL, 0x3FEEBBD8C8DF0B74ULL, 0xBFEEBBD8C8DF0B74ULL, 0x3FD1D3443F4CDB3EULL,
	0x3FEE817BAB4CD10DULL, 0x3FD35410C2E18152ULL, 0xBFD35410C2E18152ULL, 0x3FEE817BAB4CD10DULL,
	0x3FDD79775B86E389ULL, 0x3FEC678B3488739BULL, 0xBFEC678B3488739BULL, 0x3FDD79775B86E389ULL,
	0x3FE87C400FBA2EBFULL, 0x3FE49A449B9B0939ULL, 0xBFE49A449B9B0939ULL, 0x3FE87C400FBA2EBFULL,
	0x3FB5F6D00A9AA419ULL, 0x3FEFE1CAFCBD5B09ULL, 0xBFEFE1CAFCBD5B09ULL, 0x3FB5F6D00A9AA419ULL,
	0x3FEFF095658E71ADULL, 0x3FAF656E79F820E0ULL, 0xBFAF656E79F820E0ULL, 0x3FEFF095658E71ADULL,
	0x3FE5328292A35596ULL, 0x3FE7F8ECE3571771ULL, 0xBFE7F8ECE3571771ULL, 0x3FE5328292A35596ULL,
	0x3FECC1F0F3FCFC5CULL, 0x3FDC1249D8011EE7ULL, 0xBFDC1249D8011EE7ULL, 0x3FECC1F0F3FCFC5CULL,
	0x3FD4D1E24278E76AULL, 0x3FEE426A4B2BC17EULL, 0xBFEE426A4B2BC17EULL, 0x3FD4D1E24278E76AULL,
	0x3FEEF178A3E473C2ULL, 0x3FD04FB80E37FDAEULL, 0xBFD04FB80E37FDAEULL, 0x3FEEF178A3E473C2ULL,
	0x3FE01CFC874C3EB7ULL, 0x3FEBA5AA673590D2ULL, 0xBFEBA5AA673590D2ULL, 0x3FE01CFC874C3EB7ULL,
	0x3FE9777EF4C7D742ULL, 0x3FE36058B10659F3ULL, 0xBFE36058B10659F3ULL, 0x3FE9777EF4C7D742ULL,
	0x3FC139F0CEDAF577ULL, 0x3FEFB5797195D741ULL, 0xBFEFB5797195D741ULL, 0x3FC139F0CEDAF577ULL,
	0x3FEF97F924C9099BULL, 0x3FC45576B1293E5AULL, 0xBFC45576B1293E5AULL, 0x3FEF97F924C9099BULL,
	0x3FE2BEDB25FAF3EAULL, 0x3FE9EF43EF29AF94ULL, 0xBFE9EF43EF29AF94ULL, 0x3FE2BEDB25FAF3EAULL,
	0x3FEB3E4D3EF55712ULL, 0x3FE0C9704D5D898FULL, 0xBFE0C9704D5D898FULL, 0x3FEB3E4D3EF55712ULL,
	0x3FCD934FE5454311ULL, 0x3FEF2252F7763ADAULL, 0xBFEF2252F7763ADAULL, 0x3FCD934FE5454311ULL,
	0x3FEDFEAE622DBE2BULL, 0x3FD64C7DDD3F27C6ULL, 0xBFD64C7DDD3F27C6ULL, 0x3FEDFEAE622DBE2BULL,
	0x3FDAA6C82B6D3FCAULL, 0x3FED17E7743E35DCULL, 0xBFED17E7743E35DCULL, 0x3FDAA6C82B6D3FCAULL,
	0x3FE771E75F037261ULL, 0x3FE5C77BBE65018CULL, 0xBFE5C77BBE65018CULL, 0x3FE771E75F037261ULL,
	0x3FA2D865759455CDULL, 0x3FEFFA72EFFEF75DULL, 0xBFEFFA72EFFEF75DULL, 0x3FA2D865759455CDULL,
	0x3FEFFA72EFFEF75DULL, 0x3FA2D865759455CDULL, 0xBFA2D865759455CDULL, 0x3FEFFA72EFFEF75DULL,
	0x3FE5C77BBE65018CULL, 0x3FE771E75F037261ULL, 0xBFE771E75F037261ULL, 0x3FE5C77BBE65018CULL,
	0x3FED17E7743E35DCULL, 0x3FDAA6C82B6D3FCAULL, 0xBFDAA6C82B6D3FCAULL, 0x3FED17E7743E35DCULL,
	0x3FD64C7DDD3F27C6ULL, 0x3FEDFEAE622DBE2BULL, 0xBFEDFEAE622DBE2BULL, 0x3FD64C7DDD3F27C6ULL,
	0x3FEF2252F7763ADAULL, 0x3FCD934FE5454311ULL, 0xBFCD934FE5454311ULL, 0x3FEF2252F7763ADAULL,
	0x3FE0C9704D5D898FULL, 0x3FEB3E4D3EF55712ULL, 0xBFEB3E4D3EF55712ULL, 0x3FE0C9704D5D898FULL,
	0x3FE9EF43EF29AF94ULL, 0x3FE2BEDB25FAF3EAULL, 0xBFE2BEDB25FAF3EAULL, 0x3FE9EF43EF29AF94ULL,
	0x3FC45576B1293E5AULL, 0x3FEF97F924C9099BULL, 0xBFEF97F924C9099BULL, 0x3FC45576B1293E5AULL,
	0x3FEFB5797195D741ULL, 0x3FC139F0CEDAF577ULL, 0xBFC139F0CEDAF577ULL, 0x3FEFB5797195D741ULL,
	0x3FE36058B10659F3ULL, 0x3FE9777EF4C7D742ULL, 0xBFE9777EF4C7D742ULL, 0x3FE36058B10659F3ULL,
	0x3FEBA5AA673590D2ULL, 0x3FE01CFC874C3EB7ULL, 0xBFE01CFC874C3EB7ULL, 0x3FEBA5AA673590D2ULL,
	0x3FD04FB80E37FDAEULL, 0x3FEEF178A3E473C2ULL, 0xBFEEF178A3E473C2ULL, 0x3FD04FB80E37FDAEULL,
	0x3FEE426A4B2BC17EULL, 0x3FD4D1E24278E76AULL, 0xBFD4D1E24278E76AULL, 0x3FEE426A4B2BC17EULL,
	0x3FDC1249D8011EE7ULL, 0x3FECC1F0F3FCFC5CULL, 0xBFECC1F0F3FCFC5CULL, 0x3FDC1249D8011EE7ULL,
	0x3FE7F8ECE3571771ULL, 0x3FE5328292A35596ULL, 0xBFE5328292A35596ULL, 0x3FE7F8ECE3571771ULL,
	0x3FAF656E79F820E0ULL, 0x3FEFF095658E71ADULL, 0xBFEFF095658E71ADULL, 0x3FAF656E79F820E0ULL,
	0x3FEFE1CAFCBD5B09ULL, 0x3FB5F6D00A9AA419ULL, 0xBFB5F6D00A9AA419ULL, 0x3FEFE1CAFCBD5B09ULL,
	0x3FE49A449B9B0939ULL, 0x3FE87C400FBA2EBFULL, 0xBFE87C400FBA2EBFULL, 0x3FE49A449B9B0939ULL,
	0x3FEC678B3488739BULL, 0x3FDD79775B86E389ULL, 0xBFDD79775B86E389ULL, 0x3FEC678B3488739BULL,
	0x3FD35410C2E18152ULL, 0x3FEE817BAB4CD10DULL, 0xBFEE817BAB4CD10DULL, 0x3FD35410C2E18152ULL,
	0x3FEEBBD8C8DF0B74ULL, 0x3FD1D3443F4CDB3EULL, 0xBFD1D3443F4CDB3EULL, 0x3FEEBBD8C8DF0B74ULL,
	0x3FDEDC1952EF78D6ULL, 0x3FEC08C426725549ULL, 0xBFEC08C426725549ULL, 0x3FDEDC1952EF78D6ULL,
	0x3FE8FBCCA3EF940DULL, 0x3FE3FED9534556D4ULL, 0xBFE3FED9534556D4ULL, 0x3FE8FBCCA3EF940DULL,
	0x3FBC3785C79EC2D5ULL, 0x3FEFCE15FD6DA67BULL, 0xBFEFCE15FD6DA67BULL, 0x3FBC3785C79EC2D5ULL,
	0x3FEF7599A3A12077ULL, 0x3FC76DD9DE50BF31ULL, 0xBFC76DD9DE50BF31ULL, 0x3FEF7599A3A12077ULL,
	0x3FE21A799933EB59ULL, 0x3FEA63091B02FAE2ULL, 0xBFEA63091B02FAE2ULL, 0x3FE21A799933EB59ULL,
	0x3FEAD2BC9E21D511ULL, 0x3FE1734D63DEDB49ULL, 0xBFE1734D63DEDB49ULL, 0x3FEAD2BC9E21D511ULL,
	0x3FCA82A025B00451ULL, 0x3FEF4E603B0B2F2DULL, 0xBFEF4E603B0B2F2DULL, 0x3FCA82A025B00451ULL,
	0x3FEDB6526238A09BULL, 0x3FD7C3A9311DCCE7ULL, 0xBFD7C3A9311DCCE7ULL, 0x3FEDB6526238A09BULL,
	0x3FD9372A63BC93D7ULL, 0x3FED696173C9E68BULL, 0xBFED696173C9E68BULL, 0x3FD9372A63BC93D7ULL,
	0x3FE6E74454EAA8AFULL, 0x3FE6591925F0783DULL, 0xBFE6591925F0783DULL, 0x3FE6E74454EAA8AFULL,
	0x3F8921D1FCDEC784ULL, 0x3FEFFF62169B92DBULL, 0xBFEFFF62169B92DBULL, 0x3F8921D1FCDEC784ULL,
	0x3FEFFFD8858E8A92ULL, 0x3F7921F0FE670071ULL, 0xBF7921F0FE670071ULL, 0x3FEFFFD8858E8A92ULL,
	0x3FE67CF78491AF10ULL, 0x3FE6C40D73C18275ULL, 0xBFE6C40D73C18275ULL, 0x3FE67CF78491AF10ULL,
	0x3FED7D0B02B8ECF9ULL, 0x3FD8DAA52EC8A4B0ULL, 0xBFD8DAA52EC8A4B0ULL, 0x3FED7D0B02B8ECF9ULL,
	0x3FD820E3B04EAAC4ULL, 0x3FEDA383A9668988ULL, 0xBFEDA383A9668988ULL, 0x3FD820E3B04EAAC4ULL,
	0x3FEF58A2B1789E84ULL, 0x3FC9BDCBF2DC4366ULL, 0xBFC9BDCBF2DC4366ULL, 0x3FEF58A2B1789E84ULL,
	0x3FE19D5A09F2B9B8ULL, 0x3FEAB7325916C0D4ULL, 0xBFEAB7325916C0D4ULL, 0x3FE19D5A09F2B9B8ULL,
	0x3FEA7F58529FE69DULL, 0x3FE1F0F08BBC861BULL, 0xBFE1F0F08BBC861BULL, 0x3FEA7F58529FE69DULL,
	0x3FC83366E89C64C6ULL, 0x3FEF6C3F7DF5BBB7ULL, 0xBFEF6C3F7DF5BBB7ULL, 0x3FC83366E89C64C6ULL,
	0x3FEFD37914220B84ULL, 0x3FBAA7B724495C03ULL, 0xBFBAA7B724495C03ULL, 0x3FEFD37914220B84ULL,
	0x3FE425FF178E6BB1ULL, 0x3FE8DC45331698CCULL, 0xBFE8DC45331698CCULL, 0x3FE425FF178E6BB1ULL,
	0x3FEC20DE3FA971B0ULL, 0x3FDE83E0EAF85114ULL, 0xBFDE83E0EAF85114ULL, 0x3FEC20DE3FA971B0ULL,
	0x3FD233BBABC3BB71ULL, 0x3FEEADB2E8E7A88EULL, 0xBFEEADB2E8E7A88EULL, 0x3FD233BBABC3BB71ULL,
	0x3FEE9084361DF7F2ULL, 0x3FD2F422DAEC0387ULL, 0xBFD2F422DAEC0387ULL, 0x3FEE9084361DF7F2ULL,
	0x3FDDD28F1481CC58ULL, 0x3FEC5042012B6907ULL, 0xBFEC5042012B6907ULL, 0x3FDDD28F1481CC58ULL,
	0x3FE89C7E9A4DD4AAULL, 0x3FE473B51B987347ULL, 0xBFE473B51B987347ULL, 0x3FE89C7E9A4DD4AAULL,
	0x3FB787586A5D5B21ULL, 0x3FEFDD539FF1F456ULL, 0xBFEFDD539FF1F456ULL, 0x3FB787586A5D5B21ULL,
	0x3FEFF3830F8D575CULL, 0x3FAC428D12C0D7E3ULL, 0xBFAC428D12C0D7E3ULL, 0x3FEFF3830F8D575CULL,
	0x3FE5581038975137ULL, 0x3FE7D7836CC33DB2ULL, 0xBFE7D7836CC33DB2ULL, 0x3FE5581038975137ULL,
	0x3FECD7D9898B32F6ULL, 0x3FDBB7CF2304BD01ULL, 0xBFDBB7CF2304BD01ULL, 0x3FECD7D9898B32F6ULL,
	0x3FD530D880AF3C24ULL, 0x3FEE31EAE870CE25ULL, 0xBFEE31EAE870CE25ULL, 0x3FD530D880AF3C24ULL,
	0x3FEEFE220C0B95ECULL, 0x3FCFDCDC1ADFEDF9ULL, 0xBFCFDCDC1ADFEDF9ULL, 0x3FEEFE220C0B95ECULL,
	0x3FE0485626AE221AULL, 0x3FEB8C38D27504E9ULL, 0xBFEB8C38D27504E9ULL, 0x3FE0485626AE221AULL,
	0x3FE995CF2ED80D22ULL, 0x3FE338400D0C8E57ULL, 0xBFE338400D0C8E57ULL, 0x3FE995CF2ED80D22ULL,
	0x3FC20116D4EC7BCFULL, 0x3FEFAE8E8E46CFBBULL, 0xBFEFAE8E8E46CFBBULL, 0x3FC20116D4EC7BCFULL,
	0x3FEF9FCE55ADB2C8ULL, 0x3FC38EDBB0CD8D14ULL, 0xBFC38EDBB0CD8D14ULL, 0x3FEF9FCE55ADB2C8ULL,
	0x3FE2E780E3E8EA17ULL, 0x3FE9D1B1F5EA80D5ULL, 0xBFE9D1B1F5EA80D5ULL, 0x3FE2E780E3E8EA17ULL,
	0x3FEB5889FE921405ULL, 0x3FE09E907417C5E1ULL, 0xBFE09E907417C5E1ULL, 0x3FEB5889FE921405ULL,
	0x3FCE56CA1E101A1BULL, 0x3FEF168F53F7205DULL, 0xBFEF168F53F7205DULL, 0x3FCE56CA1E101A1BULL,
	0x3FEE100CCA2980ACULL, 0x3FD5EE27379EA693ULL, 0xBFD5EE27379EA693ULL, 0x3FEE100CCA2980ACULL,
	0x3FDB020D6C7F4009ULL, 0x3FED02D4FEB2BD92ULL, 0xBFED02D4FEB2BD92ULL, 0x3FDB020D6C7F4009ULL,
	0x3FE79400574F55E5ULL, 0x3FE5A28D2A5D7250ULL, 0xBFE5A28D2A5D7250ULL, 0x3FE79400574F55E5ULL,
	0x3FA5FC00D290CD43ULL, 0x3FEFF871DADB81DFULL, 0xBFEFF871DADB81DFULL, 0x3FA5FC00D290CD43ULL,
	0x3FEFFC251DF1D3F8ULL, 0x3F9F693731D1CF01ULL, 0xBF9F693731D1CF01ULL, 0x3FEFFC251DF1D3F8ULL,
	0x3FE5EC3495837074ULL, 0x3FE74F948DA8D28DULL, 0xBFE74F948DA8D28DULL, 0x3FE5EC3495837074ULL,
	0x3FED2CB220E0EF9FULL, 0x3FDA4B4127DEA1E5ULL, 0xBFDA4B4127DEA1E5ULL, 0x3FED2CB220E0EF9FULL,
	0x3FD6AA9D7DC77E17ULL, 0x3FEDED05F7DE47DAULL, 0xBFEDED05F7DE47DAULL, 0x3FD6AA9D7DC77E17ULL,
	0x3FEF2DC9C9089A9DULL, 0x3FCCCF8CB312B286ULL, 0xBFCCCF8CB312B286ULL, 0x3FEF2DC9C9089A9DULL,
	0x3FE0F426BB2A8E7EULL, 0x3FEB23CD470013B4ULL, 0xBFEB23CD470013B4ULL, 0x3FE0F426BB2A8E7EULL,
	0x3FEA0C95EABAF937ULL, 0x3FE2960727629CA8ULL, 0xBFE2960727629CA8ULL, 0x3FEA0C95EABAF937ULL,
	0x3FC51BDF8597C5F2ULL, 0x3FEF8FD5FFAE41DBULL, 0xBFEF8FD5FFAE41DBULL, 0x3FC51BDF8597C5F2ULL,
	0x3FEFBC1617E44186ULL, 0x3FC072A047BA831DULL, 0xBFC072A047BA831DULL, 0x3FEFBC1617E44186ULL,
	0x3FE3884185DFEB22ULL, 0x3FE958EFE48E6DD7ULL, 0xBFE958EFE48E6DD7ULL, 0x3FE3884185DFEB22ULL,
	0x3FEBBED7C49380EAULL, 0x3FDFE2F64BE71210ULL, 0xBFDFE2F64BE71210ULL, 0x3FEBBED7C49380EAULL,
	0x3FD0B0D9CFDBDB90ULL, 0x3FEEE482E25A9DBCULL, 0xBFEEE482E25A9DBCULL, 0x3FD0B0D9CFDBDB90ULL,
	0x3FEE529F04729FFCULL, 0x3FD472B8A5571054ULL, 0xBFD472B8A5571054ULL, 0x3FEE529F04729FFCULL,
	0x3FDC6C7F4997000BULL, 0x3FECABC169A0B900ULL, 0xBFECABC169A0B900ULL, 0x3FDC6C7F4997000BULL,
	0x3FE81A1B33B57ACCULL, 0x3FE50CC09F59A09BULL, 0xBFE50CC09F59A09BULL, 0x3FE81A1B33B57ACCULL,
	0x3FB1440134D709B3ULL, 0x3FEFED58ECB673C4ULL, 0xBFEFED58ECB673C4ULL, 0x3FB1440134D709B3ULL,
	0x3FEFE5F3AF2E3940ULL, 0x3FB4661179272096ULL, 0xBFB4661179272096ULL, 0x3FEFE5F3AF2E3940ULL,
	0x3FE4C0A145EC0004ULL, 0x3FE85BC51AE958CCULL, 0xBFE85BC51AE958CCULL, 0x3FE4C0A145EC0004ULL,
	0x3FEC7E8E52233CF3ULL, 0x3FDD2016E8E9DB5BULL, 0xBFDD2016E8E9DB5BULL, 0x3FEC7E8E52233CF3ULL,
	0x3FD3B3CEFA0414B7ULL, 0x3FEE7227DB6A9744ULL, 0xBFEE7227DB6A9744ULL, 0x3FD3B3CEFA0414B7ULL,
	0x3FEEC9B2D3C3BF84ULL, 0x3FD172A0D7765177ULL, 0xBFD172A0D7765177ULL, 0x3FEEC9B2D3C3BF84ULL,
	0x3FDF3405963FD067ULL, 0x3FEBF064E15377DDULL, 0xBFEBF064E15377DDULL, 0x3FDF3405963FD067ULL,
	0x3FE91B166FD49DA2ULL, 0x3FE3D78238C58344ULL, 0xBFE3D78238C58344ULL, 0x3FE91B166FD49DA2ULL,
	0x3FBDC70ECBAE9FC9ULL, 0x3FEFC8646CFEB721ULL, 0xBFEFC8646CFEB721ULL, 0x3FBDC70ECBAE9FC9ULL,
	0x3FEF7EA629E63D6EULL, 0x3FC6A81304F64AB2ULL, 0xBFC6A81304F64AB2ULL, 0x3FEF7EA629E63D6EULL,
	0x3FE243D5FB98AC1FULL, 0x3FEA4678C8119AC8ULL, 0xBFEA4678C8119AC8ULL, 0x3FE243D5FB98AC1FULL,
	0x3FEAEE04B43C1474ULL, 0x3FE14915AF336CEBULL, 0xBFE14915AF336CEBULL, 0x3FEAEE04B43C1474ULL,
	0x3FCB4732EF3D6722ULL, 0x3FEF43D085FF92DDULL, 0xBFEF43D085FF92DDULL, 0x3FCB4732EF3D6722ULL,
	0x3FEDC8D7CB410260ULL, 0x3FD766340F2418F6ULL, 0xBFD766340F2418F6ULL, 0x3FEDC8D7CB410260ULL,
	0x3FD993716141BDFFULL, 0x3FED556F52E93EB1ULL, 0xBFED556F52E93EB1ULL, 0x3FD993716141BDFFULL,
	0x3FE70A42B3176D7AULL, 0x3FE63503A31C1BE9ULL, 0xBFE63503A31C1BE9ULL, 0x3FE70A42B3176D7AULL,
	0x3F92D936BBE30EFDULL, 0x3FEFFE9CB44B51A1ULL, 0xBFEFFE9CB44B51A1ULL, 0x3F92D936BBE30EFDULL,
	0x3FEFFE9CB44B51A1ULL, 0x3F92D936BBE30EFDULL, 0xBF92D936BBE30EFDULL, 0x3FEFFE9CB44B51A1ULL,
	0x3FE63503A31C1BE9ULL, 0x3FE70A42B3176D7AULL, 0xBFE70A42B3176D7AULL, 0x3FE63503A31C1BE9ULL,
	0x3FED556F52E93EB1ULL, 0x3FD993716141BDFFULL, 0xBFD993716141BDFFULL, 0x3FED556F52E93EB1ULL,
	0x3FD766340F2418F6ULL, 0x3FEDC8D7CB410260ULL, 0xBFEDC8D7CB410260ULL, 0x3FD766340F2418F6ULL,
	0x3FEF43D085FF92DDULL, 0x3FCB4732EF3D6722ULL, 0xBFCB4732EF3D6722ULL, 0x3FEF43D085FF92DDULL,
	0x3FE14915AF336CEBULL, 0x3FEAEE04B43C1474ULL, 0xBFEAEE04B43C1474ULL, 0x3FE14915AF336CEBULL,
	0x3FEA4678C8119AC8ULL, 0x3FE243D5FB98AC1FULL, 0xBFE243D5FB98AC1FULL, 0x3FEA4678C8119AC8ULL,
	0x3FC6A81304F64AB2ULL, 0x3FEF7EA629E63D6EULL, 0xBFEF7EA629E63D6EULL, 0x3FC6A81304F64AB2ULL,
	0x3FEFC8646CFEB721ULL, 0x3FBDC70ECBAE9FC9ULL, 0xBFBDC70ECBAE9FC9ULL, 0x3FEFC8646CFEB721ULL,
	0x3FE3D78238C58344ULL, 0x3FE91B166FD49DA2ULL, 0xBFE91B166FD49DA2ULL, 0x3FE3D78238C58344ULL,
	0x3FEBF064E15377DDULL, 0x3FDF3405963FD067ULL, 0xBFDF3405963FD067ULL, 0x3FEBF064E15377DDULL,
	0x3FD172A0D7765177ULL, 0x3FEEC9B2D3C3BF84ULL, 0xBFEEC9B2D3C3BF84ULL, 0x3FD172A0D7765177ULL,
	0x3FEE7227DB6A9744ULL, 0x3FD3B3CEFA0414B7ULL, 0xBFD3B3CEFA0414B7ULL, 0x3FEE7227DB6A9744ULL,
	0x3FDD2016E8E9DB5BULL, 0x3FEC7E8E52233CF3ULL, 0xBFEC7E8E52233CF3ULL, 0x3FDD2016E8E9DB5BULL,
	0x3FE85BC51AE958CCULL, 0x3FE4C0A145EC0004ULL, 0xBFE4C0A145EC0004ULL, 0x3FE85BC51AE958CCULL,
	0x3FB4661179272096ULL, 0x3FEFE5F3AF2E3940ULL, 0xBFEFE5F3AF2E3940ULL, 0x3FB4661179272096ULL,
	0x3FEFED58ECB673C4ULL, 0x3FB1440134D709B3ULL, 0xBFB1440134D709B3ULL, 0x3FEFED58ECB673C4ULL,
	0x3FE50CC09F59A09BULL, 0x3FE81A1B33B57ACCULL, 0xBFE81A1B33B57ACCULL, 0x3FE50CC09F59A09BULL,
	0x3FECABC169A0B900ULL, 0x3FDC6C7F4997000BULL, 0xBFDC6C7F4997000BULL, 0x3FECABC169A0B900ULL,
	0x3FD472B8A5571054ULL, 0x3FEE529F04729FFCULL, 0xBFEE529F04729FFCULL, 0x3FD472B8A5571054ULL,
	0x3FEEE482E25A9DBCULL, 0x3FD0B0D9CFDBDB90ULL, 0xBFD0B0D9CFDBDB90ULL, 0x3FEEE482E25A9DBCULL,
	0x3FDFE2F64BE71210ULL, 0x3FEBBED7C49380EAULL, 0xBFEBBED7C49380EAULL, 0x3FDFE2F64BE71210ULL,
	0x3FE958EFE48E6DD7ULL, 0x3FE3884185DFEB22ULL, 0xBFE3884185DFEB22ULL, 0x3FE958EFE48E6DD7ULL,
	0x3FC072A047BA831DULL, 0x3FEFBC1617E44186ULL, 0xBFEFBC1617E44186ULL, 0x3FC072A047BA831DULL,
	0x3FEF8FD5FFAE41DBULL, 0x3FC51BDF8597C5F2ULL, 0xBFC51BDF8597C5F2ULL, 0x3FEF8FD5FFAE41DBULL,
	0x3FE2960727629CA8ULL, 0x3FEA0C95EABAF937ULL, 0xBFEA0C95EABAF937ULL, 0x3FE2960727629CA8ULL,
	0x3FEB23CD470013B4ULL, 0x3FE0F426BB2A8E7EULL, 0xBFE0F426BB2A8E7EULL, 0x3FEB23CD470013B4ULL,
	0x3FCCCF8CB312B286ULL, 0x3FEF2DC9C9089A9DULL, 0xBFEF2DC9C9089A9DULL, 0x3FCCCF8CB312B286ULL,
	0x3FEDED05F7DE47DAULL, 0x3FD6AA9D7DC77E17ULL, 0xBFD6AA9D7DC77E17ULL, 0x3FEDED05F7DE47DAULL,
	0x3FDA4B4127DEA1E5ULL, 0x3FED2CB220E0EF9FULL, 0xBFED2CB220E0EF9FULL, 0x3FDA4B4127DEA1E5ULL,
	0x3FE74F948DA8D28DULL, 0x3FE5EC3495837074ULL, 0xBFE5EC3495837074ULL, 0x3FE74F948DA8D28DULL,
	0x3F9F693731D1CF01ULL, 0x3FEFFC251DF1D3F8ULL, 0xBFEFFC251DF1D3F8ULL, 0x3F9F693731D1CF01ULL,
	0x3FEFF871DADB81DFULL, 0x3FA5FC00D290CD43ULL, 0xBFA5FC00D290CD43ULL, 0x3FEFF871DADB81DFULL,
	0x3FE5A28D2A5D7250ULL, 0x3FE79400574F55E5ULL, 0xBFE79400574F55E5ULL, 0x3FE5A28D2A5D7250ULL,
	0x3FED02D4FEB2BD92ULL, 0x3FDB020D6C7F4009ULL, 0xBFDB020D6C7F4009ULL, 0x3FED02D4FEB2BD92ULL,
	0x3FD5EE27379EA693ULL, 0x3FEE100CCA2980ACULL, 0xBFEE100CCA2980ACULL, 0x3FD5EE27379EA693ULL,
	0x3FEF168F53F7205DULL, 0x3FCE56CA1E101A1BULL, 0xBFCE56CA1E101A1BULL, 0x3FEF168F53F7205DULL,
	0x3FE09E907417C5E1ULL, 0x3FEB5889FE921405ULL, 0xBFEB5889FE921405ULL, 0x3FE09E907417C5E1ULL,
	0x3FE9D1B1F5EA80D5ULL, 0x3FE2E780E3E8EA17ULL, 0xBFE2E780E3E8EA17ULL, 0x3FE9D1B1F5EA80D5ULL,
	0x3FC38EDBB0CD8D14ULL, 0x3FEF9FCE55ADB2C8ULL, 0xBFEF9FCE55ADB2C8ULL, 0x3FC38EDBB0CD8D14ULL,
	0x3FEFAE8E8E46CFBBULL, 0x3FC20116D4EC7BCFULL, 0xBFC20116D4EC7BCFULL, 0x3FEFAE8E8E46CFBBULL,
	0x3FE338400D0C8E57ULL, 0x3FE995CF2ED80D22ULL, 0xBFE995CF2ED80D22ULL, 0x3FE338400D0C8E57ULL,
	0x3FEB8C38D27504E9ULL, 0x3FE0485626AE221AULL, 0xBFE0485626AE221AULL, 0x3FEB8C38D27504E9ULL,
	0x3FCFDCDC1ADFEDF9ULL, 0x3FEEFE220C0B95ECULL, 0xBFEEFE220C0B95ECULL, 0x3FCFDCDC1ADFEDF9ULL,
	0x3FEE31EAE870CE25ULL, 0x3FD530D880AF3C24ULL, 0xBFD530D880AF3C24ULL, 0x3FEE31EAE870CE25ULL,
	0x3FDBB7CF2304BD01ULL, 0x3FECD7D9898B32F6ULL, 0xBFECD7D9898B32F6ULL, 0x3FDBB7CF2304BD01ULL,
	0x3FE7D7836CC33DB2ULL, 0x3FE5581038975137ULL, 0xBFE5581038975137ULL, 0x3FE7D7836CC33DB2ULL,
	0x3FAC428D12C0D7E3ULL, 0x3FEFF3830F8D575CULL, 0xBFEFF3830F8D575CULL, 0x3FAC428D12C0D7E3ULL,
	0x3FEFDD539FF1F456ULL, 0x3FB787586A5D5B21ULL, 0xBFB787586A5D5B21ULL, 0x3FEFDD539FF1F456ULL,
	0x3FE473B51B987347ULL, 0x3FE89C7E9A4DD4AAULL, 0xBFE89C7E9A4DD4AAULL, 0x3FE473B51B987347ULL,
	0x3FEC5042012B6907ULL, 0x3FDDD28F1481CC58ULL, 0xBFDDD28F1481CC58ULL, 0x3FEC5042012B6907ULL,
	0x3FD2F422DAEC0387ULL, 0x3FEE9084361DF7F2ULL, 0xBFEE9084361DF7F2ULL, 0x3FD2F422DAEC0387ULL,
	0x3FEEADB2E8E7A88EULL, 0x3FD233BBABC3BB71ULL, 0xBFD233BBABC3BB71ULL, 0x3FEEADB2E8E7A88EULL,
	0x3FDE83E0EAF85114ULL, 0x3FEC20DE3FA971B0ULL, 0xBFEC20DE3FA971B0ULL, 0x3FDE83E0EAF85114ULL,
	0x3FE8DC45331698CCULL, 0x3FE425FF178E6BB1ULL, 0xBFE425FF178E6BB1ULL, 0x3FE8DC45331698CCULL,
	0x3FBAA7B724495C03ULL, 0x3FEFD37914220B84ULL, 0xBFEFD37914220B84ULL, 0x3FBAA7B724495C03ULL,
	0x3FEF6C3F7DF5BBB7ULL, 0x3FC83366E89C64C6ULL, 0xBFC83366E89C64C6ULL, 0x3FEF6C3F7DF5BBB7ULL,
	0x3FE1F0F08BBC861BULL, 0x3FEA7F58529FE69DULL, 0xBFEA7F58529FE69DULL, 0x3FE1F0F08BBC861BULL,
	0x3FEAB7325916C0D4ULL, 0x3FE19D5A09F2B9B8ULL, 0xBFE19D5A09F2B9B8ULL, 0x3FEAB7325916C0D4ULL,
	0x3FC9BDCBF2DC4366ULL, 0x3FEF58A2B1789E84ULL, 0xBFEF58A2B1789E84ULL, 0x3FC9BDCBF2DC4366ULL,
	0x3FEDA383A9668988ULL, 0x3FD820E3B04EAAC4ULL, 0xBFD820E3B04EAAC4ULL, 0x3FEDA383A9668988ULL,
	0x3FD8DAA52EC8A4B0ULL, 0x3FED7D0B02B8ECF9ULL, 0xBFED7D0B02B8ECF9ULL, 0x3FD8DAA52EC8A4B0ULL,
	0x3FE6C40D73C18275ULL, 0x3FE67CF78491AF10ULL, 0xBFE67CF78491AF10ULL, 0x3FE6C40D73C18275ULL,
	0x3F7921F0FE670071ULL, 0x3FEFFFD8858E8A92ULL, 0xBFEFFFD8858E8A92ULL, 0x3F7921F0FE670071ULL,
	0x3FEFFFF621621D02ULL, 0x3F6921F8BECCA4BAULL, 0xBF6921F8BECCA4BAULL, 0x3FEFFFF621621D02ULL,
	0x3FE68ED1EAA19C71ULL, 0x3FE6B25CED2FE29CULL, 0xBFE6B25CED2FE29CULL, 0x3FE68ED1EAA19C71ULL,
	0x3FED86C48445A44FULL, 0x3FD8AC4B86D5ED44ULL, 0xBFD8AC4B86D5ED44ULL, 0x3FED86C48445A44FULL,
	0x3FD84F6AAAF3903FULL, 0x3FED9A00DD8B3D46ULL, 0xBFED9A00DD8B3D46ULL, 0x3FD84F6AAAF3903FULL,
	0x3FEF5DA6ED43685DULL, 0x3FC95B49E9B62AFAULL, 0xBFC95B49E9B62AFAULL, 0x3FEF5DA6ED43685DULL,
	0x3FE1B250171373BFULL, 0x3FEAA9547A2CB98EULL, 0xBFEAA9547A2CB98EULL, 0x3FE1B250171373BFULL,
	0x3FEA8D676E545AD2ULL, 0x3FE1DC1B64DC4872ULL, 0xBFE1DC1B64DC4872ULL, 0x3FEA8D676E545AD2ULL,
	0x3FC8961727C41804ULL, 0x3FEF677556883CEEULL, 0xBFEF677556883CEEULL, 0x3FC8961727C41804ULL,
	0x3FEFD60D2DA75C9EULL, 0x3FB9DFB6EB24A85CULL, 0xBFB9DFB6EB24A85CULL, 0x3FEFD60D2DA75C9EULL,
	0x3FE4397F5B2A4380ULL, 0x3FE8CC6A75184655ULL, 0xBFE8CC6A75184655ULL, 0x3FE4397F5B2A4380ULL,
	0x3FEC2CD14931E3F1ULL, 0x3FDE57A86D3CD825ULL, 0xBFDE57A86D3CD825ULL, 0x3FEC2CD14931E3F1ULL,
	0x3FD263E6995554BAULL, 0x3FEEA68393E65800ULL, 0xBFEEA68393E65800ULL, 0x3FD263E6995554BAULL,
	0x3FEE97EC36016B30ULL, 0x3FD2C41A4E954520ULL, 0xBFD2C41A4E954520ULL, 0x3FEE97EC36016B30ULL,
	0x3FDDFEFF66A941DEULL, 0x3FEC44833141C004ULL, 0xBFEC44833141C004ULL, 0x3FDDFEFF66A941DEULL,
	0x3FE8AC871EDE1D88ULL, 0x3FE4605A692B32A2ULL, 0xBFE4605A692B32A2ULL, 0x3FE8AC871EDE1D88ULL,
	0x3FB84F8712C130A1ULL, 0x3FEFDAFA7514538CULL, 0xBFEFDAFA7514538CULL, 0x3FB84F8712C130A1ULL,
	0x3FEFF4DC54B1BED3ULL, 0x3FAAB101BD5F8317ULL, 0xBFAAB101BD5F8317ULL, 0x3FEFF4DC54B1BED3ULL,
	0x3FE56AC35197649FULL, 0x3FE7C6B89CE2D333ULL, 0xBFE7C6B89CE2D333ULL, 0x3FE56AC35197649FULL,
	0x3FECE2B32799A060ULL, 0x3FDB8A7814FD5693ULL, 0xBFDB8A7814FD5693ULL, 0x3FECE2B32799A060ULL,
	0x3FD5604012F467B4ULL, 0x3FEE298F4439197AULL, 0xBFEE298F4439197AULL, 0x3FD5604012F467B4ULL,
	0x3FEF045A14CF738CULL, 0x3FCF7B7480BD3802ULL, 0xBFCF7B7480BD3802ULL, 0x3FEF045A14CF738CULL,
	0x3FE05DF3EC31B8B7ULL, 0x3FEB7F6686E792E9ULL, 0xBFEB7F6686E792E9ULL, 0x3FE05DF3EC31B8B7ULL,
	0x3FE9A4DFA42B06B2ULL, 0x3FE32421EC49A61FULL, 0xBFE32421EC49A61FULL, 0x3FE9A4DFA42B06B2ULL,
	0x3FC264994DFD3409ULL, 0x3FEFAAFBCB0CFDDCULL, 0xBFEFAAFBCB0CFDDCULL, 0x3FC264994DFD3409ULL,
	0x3FEFA39BAC7A1791ULL, 0x3FC32B7BF94516A7ULL, 0xBFC32B7BF94516A7ULL, 0x3FEFA39BAC7A1791ULL,
	0x3FE2FBC24B441015ULL, 0x3FE9C2D110F075C2ULL, 0xBFE9C2D110F075C2ULL, 0x3FE2FBC24B441015ULL,
	0x3FEB658F14FDBC47ULL, 0x3FE089112032B08CULL, 0xBFE089112032B08CULL, 0x3FEB658F14FDBC47ULL,
	0x3FCEB86B462DE348ULL, 0x3FEF1090BC898F5FULL, 0xBFEF1090BC898F5FULL, 0x3FCEB86B462DE348ULL,
	0x3FEE18A02FDC66D9ULL, 0x3FD5BEE78B9DB3B6ULL, 0xBFD5BEE78B9DB3B6ULL, 0x3FEE18A02FDC66D9ULL,
	0x3FDB2F971DB31972ULL, 0x3FECF830E8CE467BULL, 0xBFECF830E8CE467BULL, 0x3FDB2F971DB31972ULL,
	0x3FE7A4F707BF97D2ULL, 0x3FE59001D5F723DFULL, 0xBFE59001D5F723DFULL, 0x3FE7A4F707BF97D2ULL,
	0x3FA78DBAA5874686ULL, 0x3FEFF753BB1B9164ULL, 0xBFEFF753BB1B9164ULL, 0x3FA78DBAA5874686ULL,
	0x3FEFFCE09CE2A679ULL, 0x3F9C454F4CE53B1DULL, 0xBF9C454F4CE53B1DULL, 0x3FEFFCE09CE2A679ULL,
	0x3FE5FE7CBDE56A10ULL, 0x3FE73E558E079942ULL, 0xBFE73E558E079942ULL, 0x3FE5FE7CBDE56A10ULL,
	0x3FED36FC7BCBFBDCULL, 0x3FDA1D6543B50AC0ULL, 0xBFDA1D6543B50AC0ULL, 0x3FED36FC7BCBFBDCULL,
	0x3FD6D998638A0CB6ULL, 0x3FEDE4160F6D8D81ULL, 0xBFEDE4160F6D8D81ULL, 0x3FD6D998638A0CB6ULL,
	0x3FEF33685A3AAEF0ULL, 0x3FCC6D90535D74DDULL, 0xBFCC6D90535D74DDULL, 0x3FEF33685A3AAEF0ULL,
	0x3FE1097248D0A957ULL, 0x3FEB16742A4CA2F5ULL, 0xBFEB16742A4CA2F5ULL, 0x3FE1097248D0A957ULL,
	0x3FEA1B26D2C0A75EULL, 0x3FE2818BEF4D3CBAULL, 0xBFE2818BEF4D3CBAULL, 0x3FEA1B26D2C0A75EULL,
	0x3FC57F008654CBDEULL, 0x3FEF8BA737CB4B78ULL, 0xBFEF8BA737CB4B78ULL, 0x3FC57F008654CBDEULL,
	0x3FEFBF470F0A8D88ULL, 0x3FC00EE8AD6FB85BULL, 0xBFC00EE8AD6FB85BULL, 0x3FEFBF470F0A8D88ULL,
	0x3FE39C23E3D63029ULL, 0x3FE94990E3AC4A6CULL, 0xBFE94990E3AC4A6CULL, 0x3FE39C23E3D63029ULL,
	0x3FEBCB54CB0D2327ULL, 0x3FDFB7575C24D2DEULL, 0xBFDFB7575C24D2DEULL, 0x3FEBCB54CB0D2327ULL,
	0x3FD0E15B4E1749CEULL, 0x3FEEDDEB6A078651ULL, 0xBFEEDDEB6A078651ULL, 0x3FD0E15B4E1749CEULL,
	0x3FEE5A9D550467D3ULL, 0x3FD44310DC8936F0ULL, 0xBFD44310DC8936F0ULL, 0x3FEE5A9D550467D3ULL,
	0x3FDC997FC3865389ULL, 0x3FECA08F19B9C449ULL, 0xBFECA08F19B9C449ULL, 0x3FDC997FC3865389ULL,
	0x3FE82A9C13F545FFULL, 0x3FE4F9CC25CCA486ULL, 0xBFE4F9CC25CCA486ULL, 0x3FE82A9C13F545FFULL,
	0x3FB20C9674ED444DULL, 0x3FEFEB9D2530410FULL, 0xBFEFEB9D2530410FULL, 0x3FB20C9674ED444DULL,
	0x3FEFE7EA85482D60ULL, 0x3FB39D9F12C5A299ULL, 0xBFB39D9F12C5A299ULL, 0x3FEFE7EA85482D60ULL,
	0x3FE4D3BC6D589F7FULL, 0x3FE84B7111AF83FAULL, 0xBFE84B7111AF83FAULL, 0x3FE4D3BC6D589F7FULL,
	0x3FEC89F587029C13ULL, 0x3FDCF34BAEE1CD21ULL, 0xBFDCF34BAEE1CD21ULL, 0x3FEC89F587029C13ULL,
	0x3FD3E39BE96EC271ULL, 0x3FEE6A61C55D53A7ULL, 0xBFEE6A61C55D53A7ULL, 0x3FD3E39BE96EC271ULL,
	0x3FEED0835E999009ULL, 0x3FD1423EEFC69378ULL, 0xBFD1423EEFC69378ULL, 0x3FEED0835E999009ULL,
	0x3FDF5FDEE656CDA3ULL, 0x3FEBE41B611154C1ULL, 0xBFEBE41B611154C1ULL, 0x3FDF5FDEE656CDA3ULL,
	0x3FE92AA41FC5A815ULL, 0x3FE3C3C44981C518ULL, 0xBFE3C3C44981C518ULL, 0x3FE92AA41FC5A815ULL,
	0x3FBE8EB7FDE4AA3FULL, 0x3FEFC56E3B7D9AF6ULL, 0xBFEFC56E3B7D9AF6ULL, 0x3FBE8EB7FDE4AA3FULL,
	0x3FEF830F4A40C60CULL, 0x3FC6451A831D830DULL, 0xBFC6451A831D830DULL, 0x3FEF830F4A40C60CULL,
	0x3FE258734CBB7110ULL, 0x3FEA38184A593BC6ULL, 0xBFEA38184A593BC6ULL, 0x3FE258734CBB7110ULL,
	0x3FEAFB8FD89F57B6ULL, 0x3FE133E9CFEE254FULL, 0xBFE133E9CFEE254FULL, 0x3FEAFB8FD89F57B6ULL,
	0x3FCBA96334F15DADULL, 0x3FEF3E6BBC1BBC65ULL, 0xBFEF3E6BBC1BBC65ULL, 0x3FCBA96334F15DADULL,
	0x3FEDD1FEF38A915AULL, 0x3FD73763C9261092ULL, 0xBFD73763C9261092ULL, 0x3FEDD1FEF38A915AULL,
	0x3FD9C17D440DF9F2ULL, 0x3FED4B5B1B187524ULL, 0xBFED4B5B1B187524ULL, 0x3FD9C17D440DF9F2ULL,
	0x3FE71BAC960E41BFULL, 0x3FE622E44FEC22FFULL, 0xBFE622E44FEC22FFULL, 0x3FE71BAC960E41BFULL,
	0x3F95FD4D21FAB226ULL, 0x3FEFFE1C6870CB77ULL, 0xBFEFFE1C6870CB77ULL, 0x3F95FD4D21FAB226ULL,
	0x3FEFFF0943C53BD1ULL, 0x3F8F6A296AB997CBULL, 0xBF8F6A296AB997CBULL, 0x3FEFFF0943C53BD1ULL,
	0x3FE64715437F535BULL, 0x3FE6F8CA99C95B75ULL, 0xBFE6F8CA99C95B75ULL, 0x3FE64715437F535BULL,
	0x3FED5F7172888A7FULL, 0x3FD96555B7AB948FULL, 0xBFD96555B7AB948FULL, 0x3FED5F7172888A7FULL,
	0x3FD794F5E613DFAEULL, 0x3FEDBF9E4395759AULL, 0xBFEDBF9E4395759AULL, 0x3FD794F5E613DFAEULL,
	0x3FEF492206BCABB4ULL, 0x3FCAE4F1D5F3B9ABULL, 0xBFCAE4F1D5F3B9ABULL, 0x3FEF492206BCABB4ULL,
	0x3FE15E36E4DBE2BCULL, 0x3FEAE068F345ECEFULL, 0xBFEAE068F345ECEFULL, 0x3FE15E36E4DBE2BCULL,
	0x3FEA54C91090F523ULL, 0x3FE22F2D662C13E2ULL, 0xBFE22F2D662C13E2ULL, 0x3FEA54C91090F523ULL,
	0x3FC70AFD8D08C4FFULL, 0x3FEF7A299C1A322AULL, 0xBFEF7A299C1A322AULL, 0x3FC70AFD8D08C4FFULL,
	0x3FEFCB4703914354ULL, 0x3FBCFF533B307DC1ULL, 0xBFBCFF533B307DC1ULL, 0x3FEFCB4703914354ULL,
	0x3FE3EB33EABE0680ULL, 0x3FE90B7943575EFEULL, 0xBFE90B7943575EFEULL, 0x3FE3EB33EABE0680ULL,
	0x3FEBFC9D25A1B147ULL, 0x3FDF081906BFF7FEULL, 0xBFDF081906BFF7FEULL, 0x3FEBFC9D25A1B147ULL,
	0x3FD1A2F7FBE8F243ULL, 0x3FEEC2CF4B1AF6B2ULL, 0xBFEEC2CF4B1AF6B2ULL, 0x3FD1A2F7FBE8F243ULL,
	0x3FEE79DB29A5165AULL, 0x3FD383F5E353B6ABULL, 0xBFD383F5E353B6ABULL, 0x3FEE79DB29A5165AULL,
	0x3FDD4CD02BA8609DULL, 0x3FEC7315899EAAD7ULL, 0xBFEC7315899EAAD7ULL, 0x3FDD4CD02BA8609DULL,
	0x3FE86C0A1D9AA195ULL, 0x3FE4AD79516722F1ULL, 0xBFE4AD79516722F1ULL, 0x3FE86C0A1D9AA195ULL,
	0x3FB52E774A4D4D0AULL, 0x3FEFE3E92BE9D886ULL, 0xBFEFE3E92BE9D886ULL, 0x3FB52E774A4D4D0AULL,
	0x3FEFEF0102826191ULL, 0x3FB07B614E463064ULL, 0xBFB07B614E463064ULL, 0x3FEFEF0102826191ULL,
	0x3FE51FA81CD99AA6ULL, 0x3FE8098B756E52FAULL, 0xBFE8098B756E52FAULL, 0x3FE51FA81CD99AA6ULL,
	0x3FECB6E20A00DA99ULL, 0x3FDC3F6D47263129ULL, 0xBFDC3F6D47263129ULL, 0x3FECB6E20A00DA99ULL,
	0x3FD4A253D11B82F3ULL, 0x3FEE4A8DFF81CE5EULL, 0xBFEE4A8DFF81CE5EULL, 0x3FD4A253D11B82F3ULL,
	0x3FEEEB074C50A544ULL, 0x3FD0804E05EB661EULL, 0xBFD0804E05EB661EULL, 0x3FEEEB074C50A544ULL,
	0x3FE00740C82B82E1ULL, 0x3FEBB249A0B6C40DULL, 0xBFEBB249A0B6C40DULL, 0x3FE00740C82B82E1ULL,
	0x3FE9683F42BD7FE1ULL, 0x3FE374531B817F8DULL, 0xBFE374531B817F8DULL, 0x3FE9683F42BD7FE1ULL,
	0x3FC0D64DBCB26786ULL, 0x3FEFB8D18D66ADB7ULL, 0xBFEFB8D18D66ADB7ULL, 0x3FC0D64DBCB26786ULL,
	0x3FEF93F14F85AC08ULL, 0x3FC4B8B17F79FA88ULL, 0xBFC4B8B17F79FA88ULL, 0x3FEF93F14F85AC08ULL,
	0x3FE2AA76E87AEB58ULL, 0x3FE9FDF4F13149DEULL, 0xBFE9FDF4F13149DEULL, 0x3FE2AA76E87AEB58ULL,
	0x3FEB3115A5F37BF3ULL, 0x3FE0DED0B84BC4B6ULL, 0xBFE0DED0B84BC4B6ULL, 0x3FEB3115A5F37BF3ULL,
	0x3FCD31774D2CBDEEULL, 0x3FEF2817FC4609CEULL, 0xBFEF2817FC4609CEULL, 0x3FCD31774D2CBDEEULL,
	0x3FEDF5E36A9BA59CULL, 0x3FD67B949CAD63CBULL, 0xBFD67B949CAD63CBULL, 0x3FEDF5E36A9BA59CULL,
	0x3FDA790CD3DBF31BULL, 0x3FED2255C6E5A4E1ULL, 0xBFED2255C6E5A4E1ULL, 0x3FDA790CD3DBF31BULL,
	0x3FE760C52C304764ULL, 0x3FE5D9DEE73E345CULL, 0xBFE5D9DEE73E345CULL, 0x3FE760C52C304764ULL,
	0x3FA14685DB42C17FULL, 0x3FEFFB55E425FDAEULL, 0xBFEFFB55E425FDAEULL, 0x3FA14685DB42C17FULL,
	0x3FEFF97C4208C014ULL, 0x3FA46A396FF86179ULL, 0xBFA46A396FF86179ULL, 0x3FEFF97C4208C014ULL,
	0x3FE5B50B264F7448ULL, 0x3FE782FB1B90B35BULL, 0xBFE782FB1B90B35BULL, 0x3FE5B50B264F7448ULL,
	0x3FED0D672F59D2B9ULL, 0x3FDAD473125CDC09ULL, 0xBFDAD473125CDC09ULL, 0x3FED0D672F59D2B9ULL,
	0x3FD61D595C88C202ULL, 0x3FEE0766D9280F54ULL, 0xBFEE0766D9280F54ULL, 0x3FD61D595C88C202ULL,
	0x3FEF1C7ABE284708ULL, 0x3FCDF5163F01099AULL, 0xBFCDF5163F01099AULL, 0x3FEF1C7ABE284708ULL,
	0x3FE0B405878F85ECULL, 0x3FEB4B7409DE7925ULL, 0xBFEB4B7409DE7925ULL, 0x3FE0B405878F85ECULL,
	0x3FE9E082EDB42472ULL, 0x3FE2D333D34E9BB8ULL, 0xBFE2D333D34E9BB8ULL, 0x3FE9E082EDB42472ULL,
	0x3FC3F22F57DB4893ULL, 0x3FEF9BED7CFBDE29ULL, 0xBFEF9BED7CFBDE29ULL, 0x3FC3F22F57DB4893ULL,
	0x3FEFB20DC681D54DULL, 0x3FC19D8940BE24E7ULL, 0xBFC19D8940BE24E7ULL, 0x3FEFB20DC681D54DULL,
	0x3FE34C5252C14DE1ULL, 0x3FE986AEF1457594ULL, 0xBFE986AEF1457594ULL, 0x3FE34C5252C14DE1ULL,
	0x3FEB98FA1FD9155EULL, 0x3FE032AE55EDBD96ULL, 0xBFE032AE55EDBD96ULL, 0x3FEB98FA1FD9155EULL,
	0x3FD01F1806B9FDD2ULL, 0x3FEEF7D6E51CA3C0ULL, 0xBFEEF7D6E51CA3C0ULL, 0x3FD01F1806B9FDD2ULL,
	0x3FEE3A33EC75CE85ULL, 0x3FD50163DC197048ULL, 0xBFD50163DC197048ULL, 0x3FEE3A33EC75CE85ULL,
	0x3FDBE51517FFC0D9ULL, 0x3FECCCEE20C2DEA0ULL, 0xBFECCCEE20C2DEA0ULL, 0x3FDBE51517FFC0D9ULL,
	0x3FE7E83F87B03686ULL, 0x3FE5454FF5159DFCULL, 0xBFE5454FF5159DFCULL, 0x3FE7E83F87B03686ULL,
	0x3FADD406F9808EC9ULL, 0x3FEFF21614E131EDULL, 0xBFEFF21614E131EDULL, 0x3FADD406F9808EC9ULL,
	0x3FEFDF9922F73307ULL, 0x3FB6BF1B3E79B129ULL, 0xBFB6BF1B3E79B129ULL, 0x3FEFDF9922F73307ULL,
	0x3FE48703306091FFULL, 0x3FE88C66E7481BA1ULL, 0xBFE88C66E7481BA1ULL, 0x3FE48703306091FFULL,
	0x3FEC5BEF59FEF85AULL, 0x3FDDA60C5CFA10D9ULL, 0xBFDDA60C5CFA10D9ULL, 0x3FEC5BEF59FEF85AULL,
	0x3FD3241FB638BAAFULL, 0x3FEE89095BAD6025ULL, 0xBFEE89095BAD6025ULL, 0x3FD3241FB638BAAFULL,
	0x3FEEB4CF515B8811ULL, 0x3FD2038583D727BEULL, 0xBFD2038583D727BEULL, 0x3FEEB4CF515B8811ULL,
	0x3FDEB00695F25620ULL, 0x3FEC14D9DC465E57ULL, 0xBFEC14D9DC465E57ULL, 0x3FDEB00695F25620ULL,
	0x3FE8EC109B486C49ULL, 0x3FE41272663D108CULL, 0xBFE41272663D108CULL, 0x3FE8EC109B486C49ULL,
	0x3FBB6FA6EC38F64CULL, 0x3FEFD0D158D86087ULL, 0xBFEFD0D158D86087ULL, 0x3FBB6FA6EC38F64CULL,
	0x3FEF70F6434B7EB7ULL, 0x3FC7D0A7BBD2CB1CULL, 0xBFC7D0A7BBD2CB1CULL, 0x3FEF70F6434B7EB7ULL,
	0x3FE205BAA17560D6ULL, 0x3FEA7138DE9D60F5ULL, 0xBFEA7138DE9D60F5ULL, 0x3FE205BAA17560D6ULL,
	0x3FEAC4FFBD3EFAC8ULL, 0x3FE188591F3A46E5ULL, 0xBFE188591F3A46E5ULL, 0x3FEAC4FFBD3EFAC8ULL,
	0x3FCA203E1B1831DAULL, 0x3FEF538B1FAF2D07ULL, 0xBFEF538B1FAF2D07ULL, 0x3FCA203E1B1831DAULL,
	0x3FEDACF42CE68AB9ULL, 0x3FD7F24DD37341E4ULL, 0xBFD7F24DD37341E4ULL, 0x3FEDACF42CE68AB9ULL,
	0x3FD908EF81EF7BD1ULL, 0x3FED733F508C0DFFULL, 0xBFED733F508C0DFFULL, 0x3FD908EF81EF7BD1ULL,
	0x3FE6D5AFEF4AAFCDULL, 0x3FE66B0F3F52B386ULL, 0xBFE66B0F3F52B386ULL, 0x3FE6D5AFEF4AAFCDULL,
	0x3F82D96B0E509703ULL, 0x3FEFFFA72C978C4FULL, 0xBFEFFFA72C978C4FULL, 0x3F82D96B0E509703ULL,
	0x3FEFFFA72C978C4FULL, 0x3F82D96B0E509703ULL, 0xBF82D96B0E509703ULL, 0x3FEFFFA72C978C4FULL,
	0x3FE66B0F3F52B386ULL, 0x3FE6D5AFEF4AAFCDULL, 0xBFE6D5AFEF4AAFCDULL, 0x3FE66B0F3F52B386ULL,
	0x3FED733F508C0DFFULL, 0x3FD908EF81EF7BD1ULL, 0xBFD908EF81EF7BD1ULL, 0x3FED733F508C0DFFULL,
	0x3FD7F24DD37341E4ULL, 0x3FEDACF42CE68AB9ULL, 0xBFEDACF42CE68AB9ULL, 0x3FD7F24DD37341E4ULL,
	0x3FEF538B1FAF2D07ULL, 0x3FCA203E1B1831DAULL, 0xBFCA203E1B1831DAULL, 0x3FEF538B1FAF2D07ULL,
	0x3FE188591F3A46E5ULL, 0x3FEAC4FFBD3EFAC8ULL, 0xBFEAC4FFBD3EFAC8ULL, 0x3FE188591F3A46E5ULL,
	0x3FEA7138DE9D60F5ULL, 0x3FE205BAA17560D6ULL, 0xBFE205BAA17560D6ULL, 0x3FEA7138DE9D60F5ULL,
	0x3FC7D0A7BBD2CB1CULL, 0x3FEF70F6434B7EB7ULL, 0xBFEF70F6434B7EB7ULL, 0x3FC7D0A7BBD2CB1CULL,
	0x3FEFD0D158D86087ULL, 0x3FBB6FA6EC38F64CULL, 0xBFBB6FA6EC38F64CULL, 0x3FEFD0D158D86087ULL,
	0x3FE41272663D108CULL, 0x3FE8EC109B486C49ULL, 0xBFE8EC109B486C49ULL, 0x3FE41272663D108CULL,
	0x3FEC14D9DC465E57ULL, 0x3FDEB00695F25620ULL, 0xBFDEB00695F25620ULL, 0x3FEC14D9DC465E57ULL,
	0x3FD2038583D727BEULL, 0x3FEEB4CF515B8811ULL, 0xBFEEB4CF515B8811ULL, 0x3FD2038583D727BEULL,
	0x3FEE89095BAD6025ULL, 0x3FD3241FB638BAAFULL, 0xBFD3241FB638BAAFULL, 0x3FEE89095BAD6025ULL,
	0x3FDDA60C5CFA10D9ULL, 0x3FEC5BEF59FEF85AULL, 0xBFEC5BEF59FEF85AULL, 0x3FDDA60C5CFA10D9ULL,
	0x3FE88C66E7481BA1ULL, 0x3FE48703306091FFULL, 0xBFE48703306091FFULL, 0x3FE88C66E7481BA1ULL,
	0x3FB6BF1B3E79B129ULL, 0x3FEFDF9922F73307ULL, 0xBFEFDF9922F73307ULL, 0x3FB6BF1B3E79B129ULL,
	0x3FEFF21614E131EDULL, 0x3FADD406F9808EC9ULL, 0xBFADD406F9808EC9ULL, 0x3FEFF21614E131EDULL,
	0x3FE5454FF5159DFCULL, 0x3FE7E83F87B03686ULL, 0xBFE7E83F87B03686ULL, 0x3FE5454FF5159DFCULL,
	0x3FECCCEE20C2DEA0ULL, 0x3FDBE51517FFC0D9ULL, 0xBFDBE51517FFC0D9ULL, 0x3FECCCEE20C2DEA0ULL,
	0x3FD50163DC197048ULL, 0x3FEE3A33EC75CE85ULL, 0xBFEE3A33EC75CE85ULL, 0x3FD50163DC197048ULL,
	0x3FEEF7D6E51CA3C0ULL, 0x3FD01F1806B9FDD2ULL, 0xBFD01F1806B9FDD2ULL, 0x3FEEF7D6E51CA3C0ULL,
	0x3FE032AE55EDBD96ULL, 0x3FEB98FA1FD9155EULL, 0xBFEB98FA1FD9155EULL, 0x3FE032AE55EDBD96ULL,
	0x3FE986AEF1457594ULL, 0x3FE34C5252C14DE1ULL, 0xBFE34C5252C14DE1ULL, 0x3FE986AEF1457594ULL,
	0x3FC19D8940BE24E7ULL, 0x3FEFB20DC681D54DULL, 0xBFEFB20DC681D54DULL, 0x3FC19D8940BE24E7ULL,
	0x3FEF9BED7CFBDE29ULL, 0x3FC3F22F57DB4893ULL, 0xBFC3F22F57DB4893ULL, 0x3FEF9BED7CFBDE29ULL,
	0x3FE2D333D34E9BB8ULL, 0x3FE9E082EDB42472ULL, 0xBFE9E082EDB42472ULL, 0x3FE2D333D34E9BB8ULL,
	0x3FEB4B7409DE7925ULL, 0x3FE0B405878F85ECULL, 0xBFE0B405878F85ECULL, 0x3FEB4B7409DE7925ULL,
	0x3FCDF5163F01099AULL, 0x3FEF1C7ABE284708ULL, 0xBFEF1C7ABE284708ULL, 0x3FCDF5163F01099AULL,
	0x3FEE0766D9280F54ULL, 0x3FD61D595C88C202ULL, 0xBFD61D595C88C202ULL, 0x3FEE0766D9280F54ULL,
	0x3FDAD473125CDC09ULL, 0x3FED0D672F59D2B9ULL, 0xBFED0D672F59D2B9ULL, 0x3FDAD473125CDC09ULL,
	0x3FE782FB1B90B35BULL, 0x3FE5B50B264F7448ULL, 0xBFE5B50B264F7448ULL, 0x3FE782FB1B90B35BULL,
	0x3FA46A396FF86179ULL, 0x3FEFF97C4208C014ULL, 0xBFEFF97C4208C014ULL, 0x3FA46A396FF86179ULL,
	0x3FEFFB55E425FDAEULL, 0x3FA14685DB42C17FULL, 0xBFA14685DB42C17FULL, 0x3FEFFB55E425FDAEULL,
	0x3FE5D9DEE73E345CULL, 0x3FE760C52C304764ULL, 0xBFE760C52C304764ULL, 0x3FE5D9DEE73E345CULL,
	0x3FED2255C6E5A4E1ULL, 0x3FDA790CD3DBF31BULL, 0xBFDA790CD3DBF31BULL, 0x3FED2255C6E5A4E1ULL,
	0x3FD67B949CAD63CBULL, 0x3FEDF5E36A9BA59CULL, 0xBFEDF5E36A9BA59CULL, 0x3FD67B949CAD63CBULL,
	0x3FEF2817FC4609CEULL, 0x3FCD31774D2CBDEEULL, 0xBFCD31774D2CBDEEULL, 0x3FEF2817FC4609CEULL,
	0x3FE0DED0B84BC4B6ULL, 0x3FEB3115A5F37BF3ULL, 0xBFEB3115A5F37BF3ULL, 0x3FE0DED0B84BC4B6ULL,
	0x3FE9FDF4F13149DEULL, 0x3FE2AA76E87AEB58ULL, 0xBFE2AA76E87AEB58ULL, 0x3FE9FDF4F13149DEULL,
	0x3FC4B8B17F79FA88ULL, 0x3FEF93F14F85AC08ULL, 0xBFEF93F14F85AC08ULL, 0x3FC4B8B17F79FA88ULL,
	0x3FEFB8D18D66ADB7ULL, 0x3FC0D64DBCB26786ULL, 0xBFC0D64DBCB26786ULL, 0x3FEFB8D18D66ADB7ULL,
	0x3FE374531B817F8DULL, 0x3FE9683F42BD7FE1ULL, 0xBFE9683F42BD7FE1ULL, 0x3FE374531B817F8DULL,
	0x3FEBB249A0B6C40DULL, 0x3FE00740C82B82E1ULL, 0xBFE00740C82B82E1ULL, 0x3FEBB249A0B6C40DULL,
	0x3FD0804E05EB661EULL, 0x3FEEEB074C50A544ULL, 0xBFEEEB074C50A544ULL, 0x3FD0804E05EB661EULL,
	0x3FEE4A8DFF81CE5EULL, 0x3FD4A253D11B82F3ULL, 0xBFD4A253D11B82F3ULL, 0x3FEE4A8DFF81CE5EULL,
	0x3FDC3F6D47263129ULL, 0x3FECB6E20A00DA99ULL, 0xBFECB6E20A00DA99ULL, 0x3FDC3F6D47263129ULL,
	0x3FE8098B756E52FAULL, 0x3FE51FA81CD99AA6ULL, 0xBFE51FA81CD99AA6ULL, 0x3FE8098B756E52FAULL,
	0x3FB07B614E463064ULL, 0x3FEFEF0102826191ULL, 0xBFEFEF0102826191ULL, 0x3FB07B614E463064ULL,
	0x3FEFE3E92BE9D886ULL, 0x3FB52E774A4D4D0AULL, 0xBFB52E774A4D4D0AULL, 0x3FEFE3E92BE9D886ULL,
	0x3FE4AD79516722F1ULL, 0x3FE86C0A1D9AA195ULL, 0xBFE86C0A1D9AA195ULL, 0x3FE4AD79516722F1ULL,
	0x3FEC7315899EAAD7ULL, 0x3FDD4CD02BA8609DULL, 0xBFDD4CD02BA8609DULL, 0x3FEC7315899EAAD7ULL,
	0x3FD383F5E353B6ABULL, 0x3FEE79DB29A5165AULL, 0xBFEE79DB29A5165AULL, 0x3FD383F5E353B6ABULL,
	0x3FEEC2CF4B1AF6B2ULL, 0x3FD1A2F7FBE8F243ULL, 0xBFD1A2F7FBE8F243ULL, 0x3FEEC2CF4B1AF6B2ULL,
	0x3FDF081906BFF7FEULL, 0x3FEBFC9D25A1B147ULL, 0xBFEBFC9D25A1B147ULL, 0x3FDF081906BFF7FEULL,
	0x3FE90B7943575EFEULL, 0x3FE3EB33EABE0680ULL, 0xBFE3EB33EABE0680ULL, 0x3FE90B7943575EFEULL,
	0x3FBCFF533B307DC1ULL, 0x3FEFCB4703914354ULL, 0xBFEFCB4703914354ULL, 0x3FBCFF533B307DC1ULL,
	0x3FEF7A299C1A322AULL, 0x3FC70AFD8D08C4FFULL, 0xBFC70AFD8D08C4FFULL, 0x3FEF7A299C1A322AULL,
	0x3FE22F2D662C13E2ULL, 0x3FEA54C91090F523ULL, 0xBFEA54C91090F523ULL, 0x3FE22F2D662C13E2ULL,
	0x3FEAE068F345ECEFULL, 0x3FE15E36E4DBE2BCULL, 0xBFE15E36E4DBE2BCULL, 0x3FEAE068F345ECEFULL,
	0x3FCAE4F1D5F3B9ABULL, 0x3FEF492206BCABB4ULL, 0xBFEF492206BCABB4ULL, 0x3FCAE4F1D5F3B9ABULL,
	0x3FEDBF9E4395759AULL, 0x3FD794F5E613DFAEULL, 0xBFD794F5E613DFAEULL, 0x3FEDBF9E4395759AULL,
	0x3FD96555B7AB948FULL, 0x3FED5F7172888A7FULL, 0xBFED5F7172888A7FULL, 0x3FD96555B7AB948FULL,
	0x3FE6F8CA99C95B75ULL, 0x3FE64715437F535BULL, 0xBFE64715437F535BULL, 0x3FE6F8CA99C95B75ULL,
	0x3F8F6A296AB997CBULL, 0x3FEFFF0943C53BD1ULL, 0xBFEFFF0943C53BD1ULL, 0x3F8F6A296AB997CBULL,
	0x3FEFFE1C6870CB77ULL, 0x3F95FD4D21FAB226ULL, 0xBF95FD4D21FAB226ULL, 0x3FEFFE1C6870CB77ULL,
	0x3FE622E44FEC22FFULL, 0x3FE71BAC960E41BFULL, 0xBFE71BAC960E41BFULL, 0x3FE622E44FEC22FFULL,
	0x3FED4B5B1B187524ULL, 0x3FD9C17D440DF9F2ULL, 0xBFD9C17D440DF9F2ULL, 0x3FED4B5B1B187524ULL,
	0x3FD73763C9261092ULL, 0x3FEDD1FEF38A915AULL, 0xBFEDD1FEF38A915AULL, 0x3FD73763C9261092ULL,
	0x3FEF3E6BBC1BBC65ULL, 0x3FCBA96334F15DADULL, 0xBFCBA96334F15DADULL, 0x3FEF3E6BBC1BBC65ULL,
	0x3FE133E9CFEE254FULL, 0x3FEAFB8FD89F57B6ULL, 0xBFEAFB8FD89F57B6ULL, 0x3FE133E9CFEE254FULL,
	0x3FEA38184A593BC6ULL, 0x3FE258734CBB7110ULL, 0xBFE258734CBB7110ULL, 0x3FEA38184A593BC6ULL,
	0x3FC6451A831D830DULL, 0x3FEF830F4A40C60CULL, 0xBFEF830F4A40C60CULL, 0x3FC6451A831D830DULL,
	0x3FEFC56E3B7D9AF6ULL, 0x3FBE8EB7FDE4AA3FULL, 0xBFBE8EB7FDE4AA3FULL, 0x3FEFC56E3B7D9AF6ULL,
	0x3FE3C3C44981C518ULL, 0x3FE92AA41FC5A815ULL, 0xBFE92AA41FC5A815ULL, 0x3FE3C3C44981C518ULL,
	0x3FEBE41B611154C1ULL, 0x3FDF5FDEE656CDA3ULL, 0xBFDF5FDEE656CDA3ULL, 0x3FEBE41B611154C1ULL,
	0x3FD1423EEFC69378ULL, 0x3FEED0835E999009ULL, 0xBFEED0835E999009ULL, 0x3FD1423EEFC69378ULL,
	0x3FEE6A61C55D53A7ULL, 0x3FD3E39BE96EC271ULL, 0xBFD3E39BE96EC271ULL, 0x3FEE6A61C55D53A7ULL,
	0x3FDCF34BAEE1CD21ULL, 0x3FEC89F587029C13ULL, 0xBFEC89F587029C13ULL, 0x3FDCF34BAEE1CD21ULL,
	0x3FE84B7111AF83FAULL, 0x3FE4D3BC6D589F7FULL, 0xBFE4D3BC6D589F7FULL, 0x3FE84B7111AF83FAULL,
	0x3FB39D9F12C5A299ULL, 0x3FEFE7EA85482D60ULL, 0xBFEFE7EA85482D60ULL, 0x3FB39D9F12C5A299ULL,
	0x3FEFEB9D2530410FULL, 0x3FB20C9674ED444DULL, 0xBFB20C9674ED444DULL, 0x3FEFEB9D2530410FULL,
	0x3FE4F9CC25CCA486ULL, 0x3FE82A9C13F545FFULL, 0xBFE82A9C13F545FFULL, 0x3FE4F9CC25CCA486ULL,
	0x3FECA08F19B9C449ULL, 0x3FDC997FC3865389ULL, 0xBFDC997FC3865389ULL, 0x3FECA08F19B9C449ULL,
	0x3FD44310DC8936F0ULL, 0x3FEE5A9D550467D3ULL, 0xBFEE5A9D550467D3ULL, 0x3FD44310DC8936F0ULL,
	0x3FEEDDEB6A078651ULL, 0x3FD0E15B4E1749CEULL, 0xBFD0E15B4E1749CEULL, 0x3FEEDDEB6A078651ULL,
	0x3FDFB7575C24D2DEULL, 0x3FEBCB54CB0D2327ULL, 0xBFEBCB54CB0D2327ULL, 0x3FDFB7575C24D2DEULL,
	0x3FE94990E3AC4A6CULL, 0x3FE39C23E3D63029ULL, 0xBFE39C23E3D63029ULL, 0x3FE94990E3AC4A6CULL,
	0x3FC00EE8AD6FB85BULL, 0x3FEFBF470F0A8D88ULL, 0xBFEFBF470F0A8D88ULL, 0x3FC00EE8AD6FB85BULL,
	0x3FEF8BA737CB4B78ULL, 0x3FC57F008654CBDEULL, 0xBFC57F008654CBDEULL, 0x3FEF8BA737CB4B78ULL,
	0x3FE2818BEF4D3CBAULL, 0x3FEA1B26D2C0A75EULL, 0xBFEA1B26D2C0A75EULL, 0x3FE2818BEF4D3CBAULL,
	0x3FEB16742A4CA2F5ULL, 0x3FE1097248D0A957ULL, 0xBFE1097248D0A957ULL, 0x3FEB16742A4CA2F5ULL,
	0x3FCC6D90535D74DDULL, 0x3FEF33685A3AAEF0ULL, 0xBFEF33685A3AAEF0ULL, 0x3FCC6D90535D74DDULL,
	0x3FEDE4160F6D8D81ULL, 0x3FD6D998638A0CB6ULL, 0xBFD6D998638A0CB6ULL, 0x3FEDE4160F6D8D81ULL,
	0x3FDA1D6543B50AC0ULL, 0x3FED36FC7BCBFBDCULL, 0xBFED36FC7BCBFBDCULL, 0x3FDA1D6543B50AC0ULL,
	0x3FE73E558E079942ULL, 0x3FE5FE7CBDE56A10ULL, 0xBFE5FE7CBDE56A10ULL, 0x3FE73E558E079942ULL,
	0x3F9C454F4CE53B1DULL, 0x3FEFFCE09CE2A679ULL, 0xBFEFFCE09CE2A679ULL, 0x3F9C454F4CE53B1DULL,
	0x3FEFF753BB1B9164ULL, 0x3FA78DBAA5874686ULL, 0xBFA78DBAA5874686ULL, 0x3FEFF753BB1B9164ULL,
	0x3FE59001D5F723DFULL, 0x3FE7A4F707BF97D2ULL, 0xBFE7A4F707BF97D2ULL, 0x3FE59001D5F723DFULL,
	0x3FECF830E8CE467BULL, 0x3FDB2F971DB31972ULL, 0xBFDB2F971DB31972ULL, 0x3FECF830E8CE467BULL,
	0x3FD5BEE78B9DB3B6ULL, 0x3FEE18A02FDC66D9ULL, 0xBFEE18A02FDC66D9ULL, 0x3FD5BEE78B9DB3B6ULL,
	0x3FEF1090BC898F5FULL, 0x3FCEB86B462DE348ULL, 0xBFCEB86B462DE348ULL, 0x3FEF1090BC898F5FULL,
	0x3FE089112032B08CULL, 0x3FEB658F14FDBC47ULL, 0xBFEB658F14FDBC47ULL, 0x3FE089112032B08CULL,
	0x3FE9C2D110F075C2ULL, 0x3FE2FBC24B441015ULL, 0xBFE2FBC24B441015ULL, 0x3FE9C2D110F075C2ULL,
	0x3FC32B7BF94516A7ULL, 0x3FEFA39BAC7A1791ULL, 0xBFEFA39BAC7A1791ULL, 0x3FC32B7BF94516A7ULL,
	0x3FEFAAFBCB0CFDDCULL, 0x3FC264994DFD3409ULL, 0xBFC264994DFD3409ULL, 0x3FEFAAFBCB0CFDDCULL,
	0x3FE32421EC49A61FULL, 0x3FE9A4DFA42B06B2ULL, 0xBFE9A4DFA42B06B2ULL, 0x3FE32421EC49A61FULL,
	0x3FEB7F6686E792E9ULL, 0x3FE05DF3EC31B8B7ULL, 0xBFE05DF3EC31B8B7ULL, 0x3FEB7F6686E792E9ULL,
	0x3FCF7B7480BD3802ULL, 0x3FEF045A14CF738CULL, 0xBFEF045A14CF738CULL, 0x3FCF7B7480BD3802ULL,
	0x3FEE298F4439197AULL, 0x3FD5604012F467B4ULL, 0xBFD5604012F467B4ULL, 0x3FEE298F4439197AULL,
	0x3FDB8A7814FD5693ULL, 0x3FECE2B32799A060ULL, 0xBFECE2B32799A060ULL, 0x3FDB8A7814FD5693ULL,
	0x3FE7C6B89CE2D333ULL, 0x3FE56AC35197649FULL, 0xBFE56AC35197649FULL, 0x3FE7C6B89CE2D333ULL,
	0x3FAAB101BD5F8317ULL, 0x3FEFF4DC54B1BED3ULL, 0xBFEFF4DC54B1BED3ULL, 0x3FAAB101BD5F8317ULL,
	0x3FEFDAFA7514538CULL, 0x3FB84F8712C130A1ULL, 0xBFB84F8712C130A1ULL, 0x3FEFDAFA7514538CULL,
	0x3FE4605A692B32A2ULL, 0x3FE8AC871EDE1D88ULL, 0xBFE8AC871EDE1D88ULL, 0x3FE4605A692B32A2ULL,
	0x3FEC44833141C004ULL, 0x3FDDFEFF66A941DEULL, 0xBFDDFEFF66A941DEULL, 0x3FEC44833141C004ULL,
	0x3FD2C41A4E954520ULL, 0x3FEE97EC36016B30ULL, 0xBFEE97EC36016B30ULL, 0x3FD2C41A4E954520ULL,
	0x3FEEA68393E65800ULL, 0x3FD263E6995554BAULL, 0xBFD263E6995554BAULL, 0x3FEEA68393E65800ULL,
	0x3FDE57A86D3CD825ULL, 0x3FEC2CD14931E3F1ULL, 0xBFEC2CD14931E3F1ULL, 0x3FDE57A86D3CD825ULL,
	0x3FE8CC6A75184655ULL, 0x3FE4397F5B2A4380ULL, 0xBFE4397F5B2A4380ULL, 0x3FE8CC6A75184655ULL,
	0x3FB9DFB6EB24A85CULL, 0x3FEFD60D2DA75C9EULL, 0xBFEFD60D2DA75C9EULL, 0x3FB9DFB6EB24A85CULL,
	0x3FEF677556883CEEULL, 0x3FC8961727C41804ULL, 0xBFC8961727C41804ULL, 0x3FEF677556883CEEULL,
	0x3FE1DC1B64DC4872ULL, 0x3FEA8D676E545AD2ULL, 0xBFEA8D676E545AD2ULL, 0x3FE1DC1B64DC4872ULL,
	0x3FEAA9547A2CB98EULL, 0x3FE1B250171373BFULL, 0xBFE1B250171373BFULL, 0x3FEAA9547A2CB98EULL,
	0x3FC95B49E9B62AFAULL, 0x3FEF5DA6ED43685DULL, 0xBFEF5DA6ED43685DULL, 0x3FC95B49E9B62AFAULL,
	0x3FED9A00DD8B3D46ULL, 0x3FD84F6AAAF3903FULL, 0xBFD84F6AAAF3903FULL, 0x3FED9A00DD8B3D46ULL,
	0x3FD8AC4B86D5ED44ULL, 0x3FED86C48445A44FULL, 0xBFED86C48445A44FULL, 0x3FD8AC4B86D5ED44ULL,
	0x3FE6B25CED2FE29CULL, 0x3FE68ED1EAA19C71ULL, 0xBFE68ED1EAA19C71ULL, 0x3FE6B25CED2FE29CULL,
	0x3F6921F8BECCA4BAULL, 0x3FEFFFF621621D02ULL, 0xBFEFFFF621621D02ULL, 0x3F6921F8BECCA4BAULL
};

const falcon_fpr falcon_fpr_inv_sigma[FALCON_FPR_INV_SIGMA_SIZE] =
{
	0x0000000000000000ULL, 0x3F7C48EB7E24169AULL, 0x3F7BE50A548CAED9ULL, 0x3F7B852EE09E762CULL,
	0x3F7AFC5ED3CADA36ULL, 0x3F7A7B3B0976B3EDULL, 0x3F7A011282CA9C98ULL, 0x3F798D49CE5F2736ULL,
	0x3F791F57C56ED9EEULL, 0x3F78B6C2DE64C7CAULL, 0x3F78531EF6311AE3ULL
};

const falcon_fpr falcon_fpr_sigma_min[FALCON_FPR_INV_SIGMA_SIZE] =
{
	0x0000000000000000ULL, 0x3FF1DD380644568BULL, 0x3FF21D2EDCAD8626ULL, 0x3FF25C46E1AA7C7AULL,
	0x3FF2B95C574AFB25ULL, 0x3FF314ABC7FE22B6ULL, 0x3FF36E4E3475D7C3ULL, 0x3FF3C65A66A1C224ULL,
	0x3FF41CE5358CB3A0ULL, 0x3FF47201BF1F7A75ULL, 0x3FF4C5C19990C764ULL
};

const falcon_fpr falcon_fpr_p2_tab[FALCON_FPR_GM_P2_SIZE] =
{
	0x4000000000000000ULL, 0x3FF0000000000000ULL, 0x3FE0000000000000ULL, 0x3FD0000000000000ULL,
	0x3FC0000000000000ULL, 0x3FB0000000000000ULL, 0x3FA0000000000000ULL, 0x3F90000000000000ULL,
	0x3F80000000000000ULL, 0x3F70000000000000ULL, 0x3F60000000000000ULL
};

/* fft.c */

static void falcon_fpc_add(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_re;
	falcon_fpr fpct_im;

	fpct_re = falcon_fpr_add(a_re, b_re);
	fpct_im = falcon_fpr_add(a_im, b_im);
	*d_re = fpct_re;
	*d_im = fpct_im;
}

static void falcon_fpc_sub(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_re;
	falcon_fpr fpct_im;

	fpct_re = falcon_fpr_sub(a_re, b_re);
	fpct_im = falcon_fpr_sub(a_im, b_im);
	*d_re = fpct_re;
	*d_im = fpct_im;
}

static void falcon_fpc_mul(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_a_re;
	falcon_fpr fpct_a_im;
	falcon_fpr fpct_b_re;
	falcon_fpr fpct_b_im;
	falcon_fpr fpct_d_re;
	falcon_fpr fpct_d_im;

	fpct_a_re = a_re;
	fpct_a_im = a_im;
	fpct_b_re = b_re;
	fpct_b_im = b_im;
	fpct_d_re = falcon_fpr_sub(falcon_fpr_mul(fpct_a_re, fpct_b_re), falcon_fpr_mul(fpct_a_im, fpct_b_im));
	fpct_d_im = falcon_fpr_add(falcon_fpr_mul(fpct_a_re, fpct_b_im), falcon_fpr_mul(fpct_a_im, fpct_b_re));
	*d_re = fpct_d_re;
	*d_im = fpct_d_im;
}

static void falcon_fpc_div(falcon_fpr* d_re, falcon_fpr* d_im, falcon_fpr a_re, falcon_fpr a_im, falcon_fpr b_re, falcon_fpr b_im)
{
	falcon_fpr fpct_a_re;
	falcon_fpr fpct_a_im;
	falcon_fpr fpct_b_re;
	falcon_fpr fpct_b_im;
	falcon_fpr fpct_d_re;
	falcon_fpr fpct_d_im;
	falcon_fpr fpct_m;

	fpct_a_re = a_re;
	fpct_a_im = a_im;
	fpct_b_re = b_re;
	fpct_b_im = b_im;
	fpct_m = falcon_fpr_add(falcon_fpr_sqr(fpct_b_re), falcon_fpr_sqr(fpct_b_im));
	fpct_m = falcon_fpr_inv(fpct_m);
	fpct_b_re = falcon_fpr_mul(fpct_b_re, fpct_m);
	fpct_b_im = falcon_fpr_mul(falcon_fpr_neg(fpct_b_im), fpct_m);
	fpct_d_re = falcon_fpr_sub(falcon_fpr_mul(fpct_a_re, fpct_b_re), falcon_fpr_mul(fpct_a_im, fpct_b_im));
	fpct_d_im = falcon_fpr_add(falcon_fpr_mul(fpct_a_re, fpct_b_im), falcon_fpr_mul(fpct_a_im, fpct_b_re));
	*d_re = fpct_d_re;
	*d_im = fpct_d_im;
}

static void falcon_FFT(falcon_fpr* f, uint32_t logn)
{
	/*
	 * FFT algorithm in bit-reversal order uses the following
	 * iterative algorithm:
	 *
	 *   t = N
	 *   for m = 1; m < N; m *= 2:
	 *       ht = t/2
	 *       for i1 = 0; i1 < m; i1 ++:
	 *           j1 = i1 * t
	 *           s = GM[m + i1]
	 *           for j = j1; j < (j1 + ht); j ++:
	 *               x = f[j]
	 *               y = s * f[j + ht]
	 *               f[j] = x + y
	 *               f[j + ht] = x - y
	 *       t = ht
	 *
	 * GM[k] contains w^rev(k) for primitive root w = exp(i*pi/N).
	 *
	 * In the description above, f[] is supposed to contain complex
	 * numbers. In our in-memory representation, the real and
	 * imaginary parts of f[k] are in array slots k and k+N/2.
	 *
	 * We only keep the first half of the complex numbers. We can
	 * see that after the first iteration, the first and second halves
	 * of the array of complex numbers have separate lives, so we
	 * simply ignore the second part.
	 */

	uint32_t u;
	size_t t;
	size_t n;
	size_t hn;
	size_t m;

	/*
	 * First iteration: compute f[j] + i * f[j+N/2] for all j < N/2
	 * (because GM[1] = w^rev(1) = w^(N/2) = i).
	 * In our chosen representation, this is a no-op: everything is
	 * already where it should be.
	 */

	 /*
	  * Subsequent iterations are truncated to use only the first
	  * half of values.
	  */
	n = (size_t)1 << logn;
	hn = n >> 1;
	t = hn;

	for (u = 1, m = 2; u < logn; u++, m <<= 1)
	{
		size_t ht;
		size_t hm;
		size_t i1;
		size_t j1;

		ht = t >> 1;
		hm = m >> 1;

		for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t)
		{
			size_t j;
			size_t j2;
			falcon_fpr s_re;
			falcon_fpr s_im;

			j2 = j1 + ht;
			s_re = falcon_fpr_gm_tab[(m + i1) << 1];
			s_im = falcon_fpr_gm_tab[((m + i1) << 1) + 1];

			for (j = j1; j < j2; ++j)
			{
				falcon_fpr x_re;
				falcon_fpr x_im;
				falcon_fpr y_re;
				falcon_fpr y_im;

				x_re = f[j];
				x_im = f[j + hn];
				y_re = f[j + ht];
				y_im = f[j + ht + hn];
				falcon_fpc_mul(&y_re, &y_im, y_re, y_im, s_re, s_im);
				falcon_fpc_add(&f[j], &f[j + hn], x_re, x_im, y_re, y_im);
				falcon_fpc_sub(&f[j + ht], &f[j + ht + hn], x_re, x_im, y_re, y_im);
			}
		}

		t = ht;
	}
}

static void falcon_iFFT(falcon_fpr* f, uint32_t logn)
{
	/*
	 * Inverse FFT algorithm in bit-reversal order uses the following
	 * iterative algorithm:
	 *
	 *   t = 1
	 *   for m = N; m > 1; m /= 2:
	 *       hm = m/2
	 *       dt = t*2
	 *       for i1 = 0; i1 < hm; i1 ++:
	 *           j1 = i1 * dt
	 *           s = iGM[hm + i1]
	 *           for j = j1; j < (j1 + t); j ++:
	 *               x = f[j]
	 *               y = f[j + t]
	 *               f[j] = x + y
	 *               f[j + t] = s * (x - y)
	 *       t = dt
	 *   for i1 = 0; i1 < N; i1 ++:
	 *       f[i1] = f[i1] / N
	 *
	 * iGM[k] contains (1/w)^rev(k) for primitive root w = exp(i*pi/N)
	 * (actually, iGM[k] = 1/GM[k] = conj(GM[k])).
	 *
	 * In the main loop (not counting the final division loop), in
	 * all iterations except the last, the first and second half of f[]
	 * (as an array of complex numbers) are separate. In our chosen
	 * representation, we do not keep the second half.
	 *
	 * The last iteration recombines the recomputed half with the
	 * implicit half, and should yield only real numbers since the
	 * target polynomial is real; moreover, s = i at that step.
	 * Thus, when considering x and y:
	 *    y = conj(x) since the final f[j] must be real
	 *    Therefore, f[j] is filled with 2*Re(x), and f[j + t] is
	 *    filled with 2*Im(x).
	 * But we already have Re(x) and Im(x) in array slots j and j+t
	 * in our chosen representation. That last iteration is thus a
	 * simple doubling of the values in all the array.
	 *
	 * We make the last iteration a no-op by tweaking the final
	 * division into a division by N/2, not N.
	 */

	size_t hn;
	size_t m;
	size_t n;
	size_t u;
	size_t t;

	n = (size_t)1 << logn;
	t = 1;
	m = n;
	hn = n >> 1;

	for (u = logn; u > 1; u--)
	{
		size_t dt;
		size_t hm;
		size_t i1;
		size_t j1;

		hm = m >> 1;
		dt = t << 1;

		for (i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt)
		{
			falcon_fpr s_re;
			falcon_fpr s_im;
			falcon_fpr ftmp;
			size_t j;
			size_t j2;

			j2 = j1 + t;
			s_re = falcon_fpr_gm_tab[(hm + i1) << 1];
			ftmp = falcon_fpr_gm_tab[((hm + i1) << 1) + 1];
			s_im = falcon_fpr_neg(ftmp);

			for (j = j1; j < j2; ++j)
			{
				falcon_fpr x_re;
				falcon_fpr x_im;
				falcon_fpr y_re;
				falcon_fpr y_im;

				x_re = f[j];
				x_im = f[j + hn];
				y_re = f[j + t];
				y_im = f[j + t + hn];
				falcon_fpc_add(&f[j], &f[j + hn], x_re, x_im, y_re, y_im);
				falcon_fpc_sub(&x_re, &x_im, x_re, x_im, y_re, y_im);
				falcon_fpc_mul(&f[j + t], &f[j + t + hn], x_re, x_im, s_re, s_im);
			}
		}

		t = dt;
		m = hm;
	}

	/*
	 * Last iteration is a no-op, provided that we divide by N/2
	 * instead of N. We need to make a special case for logn = 0.
	 */
	if (logn > 0)
	{
		falcon_fpr ni;

		ni = falcon_fpr_p2_tab[logn];

		for (u = 0; u < n; u++)
		{
			f[u] = falcon_fpr_mul(f[u], ni);
		}
	}
}

static void falcon_poly_add(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		a[u] = falcon_fpr_add(a[u], b[u]);
	}
}

static void falcon_poly_sub(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		a[u] = falcon_fpr_sub(a[u], b[u]);
	}
}

static void falcon_poly_neg(falcon_fpr* a, uint32_t logn)
{
	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		a[u] = falcon_fpr_neg(a[u]);
	}
}

static void falcon_poly_adj_fft(falcon_fpr* a, uint32_t logn)
{
	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = (n >> 1); u < n; ++u)
	{
		a[u] = falcon_fpr_neg(a[u]);
	}
}

static void falcon_poly_mul_fft(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		falcon_fpc_mul(&a[u], &a[u + hn], a_re, a_im, b_re, b_im);
	}
}

static void falcon_poly_muladj_fft(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = falcon_fpr_neg(b[u + hn]);
		falcon_fpc_mul(&a[u], &a[u + hn], a_re, a_im, b_re, b_im);
	}
}

static void falcon_poly_mulselfadj_fft(falcon_fpr* a, uint32_t logn)
{
	/*
	 * Since each coefficient is multiplied with its own conjugate,
	 * the result contains only real values.
	 */
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;

		a_re = a[u];
		a_im = a[u + hn];
		a[u] = falcon_fpr_add(falcon_fpr_sqr(a_re), falcon_fpr_sqr(a_im));
		a[u + hn] = falcon_fpr_zero;
	}
}

static void falcon_poly_mulconst(falcon_fpr* a, falcon_fpr x, uint32_t logn)
{
	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		a[u] = falcon_fpr_mul(a[u], x);
	}
}

static void falcon_poly_invnorm2_fft(falcon_fpr* restrict d, const falcon_fpr* restrict a, const falcon_fpr *restrict b, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_im;
		falcon_fpr b_re;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		d[u] = falcon_fpr_inv(falcon_fpr_add(falcon_fpr_add(falcon_fpr_sqr(a_re), falcon_fpr_sqr(a_im)), falcon_fpr_add(falcon_fpr_sqr(b_re), falcon_fpr_sqr(b_im))));
	}
}

static void falcon_poly_add_muladj_fft(falcon_fpr* restrict d, const falcon_fpr* restrict F, const falcon_fpr* restrict G,
	const falcon_fpr* restrict f, const falcon_fpr* restrict g, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr F_re;
		falcon_fpr F_im;
		falcon_fpr G_re;
		falcon_fpr G_im;
		falcon_fpr f_re;
		falcon_fpr f_im;
		falcon_fpr g_re;
		falcon_fpr g_im;
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;

		F_re = F[u];
		F_im = F[u + hn];
		G_re = G[u];
		G_im = G[u + hn];
		f_re = f[u];
		f_im = f[u + hn];
		g_re = g[u];
		g_im = g[u + hn];

		falcon_fpc_mul(&a_re, &a_im, F_re, F_im, f_re, falcon_fpr_neg(f_im));
		falcon_fpc_mul(&b_re, &b_im, G_re, G_im, g_re, falcon_fpr_neg(g_im));
		d[u] = falcon_fpr_add(a_re, b_re);
		d[u + hn] = falcon_fpr_add(a_im, b_im);
	}
}

static void falcon_poly_mul_autoadj_fft(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		a[u] = falcon_fpr_mul(a[u], b[u]);
		a[u + hn] = falcon_fpr_mul(a[u + hn], b[u]);
	}
}

static void falcon_poly_div_autoadj_fft(falcon_fpr* restrict a, const falcon_fpr* restrict b, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr ib;

		ib = falcon_fpr_inv(b[u]);
		a[u] = falcon_fpr_mul(a[u], ib);
		a[u + hn] = falcon_fpr_mul(a[u + hn], ib);
	}
}

static void falcon_poly_LDL_fft(const falcon_fpr* restrict g00, falcon_fpr* restrict g01, falcon_fpr* restrict g11, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr g00_re;
		falcon_fpr g00_im;
		falcon_fpr g01_re;
		falcon_fpr g01_im;
		falcon_fpr g11_re;
		falcon_fpr g11_im;
		falcon_fpr mu_re;
		falcon_fpr mu_im;

		g00_re = g00[u];
		g00_im = g00[u + hn];
		g01_re = g01[u];
		g01_im = g01[u + hn];
		g11_re = g11[u];
		g11_im = g11[u + hn];
		falcon_fpc_div(&mu_re, &mu_im, g01_re, g01_im, g00_re, g00_im);
		falcon_fpc_mul(&g01_re, &g01_im, mu_re, mu_im, g01_re, falcon_fpr_neg(g01_im));
		falcon_fpc_sub(&g11[u], &g11[u + hn], g11_re, g11_im, g01_re, g01_im);
		g01[u] = mu_re;
		g01[u + hn] = falcon_fpr_neg(mu_im);
	}
}

static void falcon_poly_split_fft(falcon_fpr* restrict f0, falcon_fpr* restrict f1, const falcon_fpr* restrict f, uint32_t logn)
{
	/*
	* The FFT representation we use is in bit-reversed order
	* (element i contains f(w^(rev(i))), where rev() is the
	* bit-reversal function over the ring degree. This changes
	* indexes with regards to the Falcon specification.
	*/

	size_t n;
	size_t hn;
	size_t qn;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	/*
	 * We process complex values by pairs. For logn = 1, there is only
	 * one complex value (the other one is the implicit conjugate),
	 * so we add the two lines below because the loop will be
	 * skipped.
	 */
	f0[0] = f[0];
	f1[0] = f[hn];

	for (u = 0; u < qn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;
		falcon_fpr t_re;
		falcon_fpr t_im;
		falcon_fpr ftmp1;
		falcon_fpr ftmp2;

		a_re = f[u << 1];
		a_im = f[(u << 1) + hn];
		b_re = f[(u << 1) + 1];
		b_im = f[(u << 1) + 1 + hn];

		falcon_fpc_add(&t_re, &t_im, a_re, a_im, b_re, b_im);
		f0[u] = falcon_fpr_half(t_re);
		f0[u + qn] = falcon_fpr_half(t_im);

		falcon_fpc_sub(&t_re, &t_im, a_re, a_im, b_re, b_im);
		ftmp1 = falcon_fpr_gm_tab[(u + hn) << 1];
		ftmp2 = falcon_fpr_gm_tab[((u + hn) << 1) + 1];
		falcon_fpc_mul(&t_re, &t_im, t_re, t_im, ftmp1, falcon_fpr_neg(ftmp2));
		f1[u] = falcon_fpr_half(t_re);
		f1[u + qn] = falcon_fpr_half(t_im);
	}
}

static void falcon_poly_merge_fft(falcon_fpr* restrict f, const falcon_fpr* restrict f0, const falcon_fpr* restrict f1, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t qn;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	/*
	 * An extra copy to handle the special case logn = 1.
	 */
	f[0] = f0[0];
	f[hn] = f1[0];

	for (u = 0; u < qn; ++u)
	{
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;
		falcon_fpr t_re;
		falcon_fpr t_im;
		falcon_fpr ftmp1;
		falcon_fpr ftmp2;

		a_re = f0[u];
		a_im = f0[u + qn];
		ftmp2 = falcon_fpr_gm_tab[((u + hn) << 1) + 1];
		ftmp1 = falcon_fpr_gm_tab[(u + hn) << 1];
		falcon_fpc_mul(&b_re, &b_im, f1[u], f1[u + qn], ftmp1, ftmp2);
		falcon_fpc_add(&t_re, &t_im, a_re, a_im, b_re, b_im);
		f[u << 1] = t_re;
		f[(u << 1) + hn] = t_im;
		falcon_fpc_sub(&t_re, &t_im, a_re, a_im, b_re, b_im);
		f[(u << 1) + 1] = t_re;
		f[(u << 1) + 1 + hn] = t_im;
	}
}

/* verify.c */

const uint16_t falcon_GMb[FALCON_GMB_SIZE] =
{
	0x0FFBU, 0x1ED0U, 0x2B34U, 0x2BC8U, 0x1B30U, 0x10F6U, 0x1883U, 0x261FU,
	0x0637U, 0x18FFU, 0x2505U, 0x1492U, 0x024AU, 0x16C1U, 0x1D72U, 0x25EEU,
	0x046EU, 0x1907U, 0x06AFU, 0x03C5U, 0x1BBBU, 0x1DFAU, 0x0E9FU, 0x192AU,
	0x28AEU, 0x1FA4U, 0x075DU, 0x0698U, 0x0554U, 0x2859U, 0x27B4U, 0x23DCU,
	0x2FB2U, 0x1860U, 0x03E5U, 0x0075U, 0x12AFU, 0x1137U, 0x060DU, 0x1BA0U,
	0x0B0DU, 0x193AU, 0x114FU, 0x22ADU, 0x1BE8U, 0x0A04U, 0x1620U, 0x0FCAU,
	0x2F9DU, 0x01B0U, 0x29FFU, 0x04D5U, 0x1DBAU, 0x05FEU, 0x0F8FU, 0x1EB7U,
	0x0885U, 0x18A4U, 0x2210U, 0x19AAU, 0x12EBU, 0x069AU, 0x000EU, 0x0F20U,
	0x15C1U, 0x2498U, 0x2F83U, 0x07E3U, 0x1D77U, 0x090BU, 0x1241U, 0x1CACU,
	0x0611U, 0x0484U, 0x20D1U, 0x2C7DU, 0x03FCU, 0x0B97U, 0x2A14U, 0x1B85U,
	0x0CF4U, 0x2BE4U, 0x14A5U, 0x2D3AU, 0x298DU, 0x2766U, 0x2515U, 0x1824U,
	0x243DU, 0x17F2U, 0x0CFBU, 0x0373U, 0x28E5U, 0x01E9U, 0x05DEU, 0x0B23U,
	0x2B35U, 0x2601U, 0x0AB6U, 0x2FD1U, 0x136AU, 0x28F1U, 0x275EU, 0x04ABU,
	0x02DAU, 0x06E2U, 0x0F0EU, 0x07EEU, 0x1704U, 0x2AAAU, 0x233CU, 0x149AU,
	0x23DBU, 0x0E14U, 0x0EC6U, 0x27DEU, 0x0C6CU, 0x0D8BU, 0x123CU, 0x098EU,
	0x1DBDU, 0x24AAU, 0x0342U, 0x1E17U, 0x1AB4U, 0x0D4BU, 0x14E7U, 0x2FF4U,
	0x0DFCU, 0x06CBU, 0x2A44U, 0x263BU, 0x27E1U, 0x0FE6U, 0x2FDAU, 0x214DU,
	0x28A1U, 0x0ABDU, 0x1CAAU, 0x294EU, 0x1798U, 0x03AFU, 0x2472U, 0x05C5U,
	0x1AD1U, 0x25C4U, 0x0E01U, 0x19E9U, 0x2F71U, 0x0FDFU, 0x0E64U, 0x1E00U,
	0x1FFCU, 0x1AF6U, 0x0DCDU, 0x264FU, 0x17CAU, 0x02D7U, 0x2773U, 0x1B5BU,
	0x1B21U, 0x079DU, 0x2603U, 0x293FU, 0x17A9U, 0x017AU, 0x1EBFU, 0x223BU,
	0x22C5U, 0x240DU, 0x228EU, 0x11C7U, 0x2575U, 0x2D90U, 0x1DCEU, 0x2275U,
	0x1630U, 0x135CU, 0x186BU, 0x20C4U, 0x27ACU, 0x2213U, 0x0925U, 0x0C57U,
	0x05BBU, 0x1554U, 0x2169U, 0x1E67U, 0x0A59U, 0x0910U, 0x234CU, 0x182CU,
	0x02E1U, 0x0E72U, 0x125BU, 0x1679U, 0x2356U, 0x0E67U, 0x0010U, 0x0392U,
	0x1442U, 0x2923U, 0x11C8U, 0x07ACU, 0x0DB5U, 0x20F4U, 0x1D5CU, 0x1505U,
	0x29EDU, 0x0CD1U, 0x1B7DU, 0x0424U, 0x0B4FU, 0x1BF4U, 0x22B7U, 0x14EDU,
	0x1909U, 0x2005U, 0x0B92U, 0x18E7U, 0x13C8U, 0x19EAU, 0x15F9U, 0x0116U,
	0x03A4U, 0x27F5U, 0x22DFU, 0x1DDAU, 0x015FU, 0x2452U, 0x00EDU, 0x16E2U,
	0x1E0CU, 0x0C4AU, 0x2F5EU, 0x1DA2U, 0x0805U, 0x2C15U, 0x0EDAU, 0x1454U,
	0x11FAU, 0x06D4U, 0x2C24U, 0x0154U, 0x0E7FU, 0x1206U, 0x012CU, 0x2AF1U,
	0x13CEU, 0x2741U, 0x2D60U, 0x2FD7U, 0x1CFDU, 0x29D3U, 0x1672U, 0x1616U,
	0x0EFBU, 0x15B1U, 0x04C8U, 0x211CU, 0x2415U, 0x0F05U, 0x00FAU, 0x2BC9U,
	0x1081U, 0x18B6U, 0x25D0U, 0x2FDEU, 0x1028U, 0x0ADAU, 0x02B4U, 0x2268U,
	0x190AU, 0x1A3EU, 0x2779U, 0x28B2U, 0x0EAFU, 0x1CBCU, 0x2C61U, 0x20F1U,
	0x1925U, 0x0E44U, 0x18C6U, 0x2312U, 0x150FU, 0x08E0U, 0x194CU, 0x1CF8U,
	0x20E2U, 0x2A48U, 0x2ED2U, 0x1665U, 0x036CU, 0x1B76U, 0x0877U, 0x0984U,
	0x0D72U, 0x2401U, 0x200EU, 0x12FAU, 0x174CU, 0x0ABAU, 0x1C0AU, 0x059AU,
	0x1CDDU, 0x22AFU, 0x29A5U, 0x2CC1U, 0x107CU, 0x0598U, 0x2A50U, 0x10E8U,
	0x216DU, 0x074BU, 0x24EEU, 0x0970U, 0x0EE8U, 0x2374U, 0x02AEU, 0x1511U,
	0x09DBU, 0x10F3U, 0x17E3U, 0x026BU, 0x03A9U, 0x0B12U, 0x1E5FU, 0x0CCFU,
	0x093BU, 0x1D40U, 0x17E0U, 0x13C0U, 0x0338U, 0x27DCU, 0x2DAAU, 0x0459U,
	0x0AA7U, 0x2678U, 0x0380U, 0x07ECU, 0x13D3U, 0x0A5EU, 0x28E0U, 0x1ECCU,
	0x2F89U, 0x153AU, 0x0BFEU, 0x1900U, 0x23ACU, 0x2D98U, 0x2F79U, 0x11A8U,
	0x04F9U, 0x260BU, 0x2CCCU, 0x26D1U, 0x2737U, 0x25F8U, 0x08D6U, 0x24B7U,
	0x2BB8U, 0x013BU, 0x119FU, 0x0486U, 0x17ADU, 0x1A5FU, 0x2E59U, 0x0165U,
	0x1CC7U, 0x11C6U, 0x03D7U, 0x2156U, 0x20A0U, 0x278EU, 0x1D6AU, 0x2425U,
	0x110FU, 0x1465U, 0x0F9FU, 0x2249U, 0x0C59U, 0x1B4EU, 0x1022U, 0x2D84U,
	0x0D2EU, 0x2CD5U, 0x06D9U, 0x0124U, 0x21E9U, 0x0AF6U, 0x288AU, 0x2F9CU,
	0x16A8U, 0x2E23U, 0x0C6DU, 0x07C4U, 0x0400U, 0x247CU, 0x09ADU, 0x2AB0U,
	0x11E6U, 0x1A5EU, 0x0E23U, 0x157FU, 0x1471U, 0x099FU, 0x2116U, 0x1DE2U,
	0x1F1CU, 0x18FBU, 0x042FU, 0x04F8U, 0x0D92U, 0x2B25U, 0x0CDBU, 0x2C50U,
	0x2136U, 0x2506U, 0x266DU, 0x04E5U, 0x0741U, 0x1859U, 0x1270U, 0x2D29U,
	0x1792U, 0x2659U, 0x0D0BU, 0x0705U, 0x0B3FU, 0x1862U, 0x1450U, 0x0842U,
	0x1F1AU, 0x2489U, 0x2C63U, 0x1563U, 0x17C4U, 0x2581U, 0x100CU, 0x1C9BU,
	0x28C6U, 0x24FFU, 0x04F7U, 0x0198U, 0x1AFFU, 0x0C07U, 0x0168U, 0x2054U,
	0x2D0FU, 0x23C4U, 0x2359U, 0x2D13U, 0x0352U, 0x21A9U, 0x0310U, 0x1EEFU,
	0x208EU, 0x2F8AU, 0x0736U, 0x27E5U, 0x2F98U, 0x1E93U, 0x2E7FU, 0x15E0U,
	0x2633U, 0x03F4U, 0x02D1U, 0x0AE0U, 0x1A14U, 0x1998U, 0x14E4U, 0x1148U,
	0x1AA0U, 0x20D5U, 0x26E7U, 0x141EU, 0x0934U, 0x15B0U, 0x1493U, 0x0535U,
	0x2261U, 0x25BDU, 0x1C8CU, 0x169CU, 0x132EU, 0x038DU, 0x2D5DU, 0x112BU,
	0x202EU, 0x1A1EU, 0x10CEU, 0x0BE4U, 0x08EDU, 0x2FD9U, 0x07ABU, 0x2400U,
	0x10C8U, 0x2E8EU, 0x02B7U, 0x1113U, 0x2641U, 0x1314U, 0x096BU, 0x27F6U,
	0x0A5AU, 0x0349U, 0x0F32U, 0x27F7U, 0x1C50U, 0x2139U, 0x2BBCU, 0x1A20U,
	0x0FDBU, 0x17ACU, 0x0E66U, 0x1272U, 0x2E4DU, 0x16B8U, 0x1B92U, 0x1AD4U,
	0x2B81U, 0x1EF6U, 0x131EU, 0x2FFCU, 0x1006U, 0x0F44U, 0x0E1AU, 0x197DU,
	0x1F02U, 0x1F2EU, 0x2EC9U, 0x1A63U, 0x0219U, 0x11D2U, 0x0657U, 0x2023U,
	0x2CBDU, 0x1D78U, 0x038AU, 0x2E28U, 0x254CU, 0x2A6AU, 0x25E7U, 0x0AFFU,
	0x2DD8U, 0x1A9DU, 0x1B43U, 0x0333U, 0x22C7U, 0x187FU, 0x2A5BU, 0x015CU,
	0x1D5AU, 0x2093U, 0x1927U, 0x02B6U, 0x0354U, 0x161BU, 0x0ADDU, 0x0E84U,
	0x2D45U, 0x0BD0U, 0x05F3U, 0x21D3U, 0x1012U, 0x29F2U, 0x0CE7U, 0x16FDU,
	0x0BA2U, 0x1C79U, 0x2E6CU, 0x23A3U, 0x246BU, 0x2E36U, 0x0062U, 0x09DEU,
	0x0844U, 0x1023U, 0x2C8FU, 0x0734U, 0x0E3DU, 0x0F4CU, 0x1FC5U, 0x08B0U,
	0x2A77U, 0x1F9CU, 0x25B3U, 0x1765U, 0x1BE4U, 0x2120U, 0x0686U, 0x009FU,
	0x2AABU, 0x1336U, 0x0080U, 0x1C90U, 0x02D5U, 0x23C5U, 0x138EU, 0x18F9U,
	0x0DA6U, 0x179BU, 0x2ADCU, 0x1825U, 0x2E3EU, 0x0D5FU, 0x2912U, 0x1DF4U,
	0x0E6DU, 0x1A02U, 0x1AF9U, 0x2EB1U, 0x27E4U, 0x2E92U, 0x238DU, 0x20ADU,
	0x13F6U, 0x002DU, 0x0960U, 0x0781U, 0x1119U, 0x0AA0U, 0x069FU, 0x0033U,
	0x0AF8U, 0x028AU, 0x0768U, 0x270DU, 0x26F3U, 0x2ECCU, 0x1FA2U, 0x12E1U,
	0x1027U, 0x10A1U, 0x16CEU, 0x129DU, 0x2AE9U, 0x2D0CU, 0x024EU, 0x2FA6U,
	0x01E2U, 0x2F8DU, 0x07D6U, 0x1B98U, 0x2722U, 0x0F48U, 0x2EF0U, 0x2917U,
	0x2C62U, 0x1B2AU, 0x08A2U, 0x011CU, 0x1525U, 0x19C9U, 0x0F19U, 0x2863U,
	0x2BB4U, 0x1857U, 0x0205U, 0x255CU, 0x2C11U, 0x0F17U, 0x04BAU, 0x11FCU,
	0x1FE0U, 0x2CB7U, 0x0099U, 0x1C24U, 0x1683U, 0x13E1U, 0x2420U, 0x2F7AU,
	0x2DE4U, 0x054AU, 0x1A10U, 0x00B3U, 0x159CU, 0x0A56U, 0x1735U, 0x2F99U,
	0x035EU, 0x0C56U, 0x01DDU, 0x1C6FU, 0x162EU, 0x1EEAU, 0x109EU, 0x012EU,
	0x0B4DU, 0x2782U, 0x1AEAU, 0x2558U, 0x25AFU, 0x2E81U, 0x1002U, 0x2660U,
	0x281DU, 0x0549U, 0x29DBU, 0x14CDU, 0x186EU, 0x0F6FU, 0x070FU, 0x1931U,
	0x1427U, 0x051CU, 0x207BU, 0x0D4CU, 0x0755U, 0x04CFU, 0x0070U, 0x18FEU,
	0x2DCCU, 0x2FF0U, 0x1C76U, 0x05B3U, 0x2FF2U, 0x26A8U, 0x0D80U, 0x0320U,
	0x0575U, 0x29B6U, 0x0067U, 0x1CFCU, 0x1F28U, 0x03A8U, 0x02FCU, 0x0278U,
	0x1F3CU, 0x201FU, 0x20FDU, 0x1E4EU, 0x2A76U, 0x2563U, 0x09CCU, 0x079AU,
	0x197CU, 0x27AEU, 0x0414U, 0x10F2U, 0x0999U, 0x0E39U, 0x067BU, 0x102BU,
	0x1250U, 0x2605U, 0x2B8CU, 0x0F6AU, 0x0822U, 0x148DU, 0x07F4U, 0x2E4AU,
	0x1DD4U, 0x2FCCU, 0x14F6U, 0x094CU, 0x0577U, 0x1E28U, 0x0834U, 0x0C91U,
	0x2AA0U, 0x22C2U, 0x1D9AU, 0x2EDBU, 0x0AE7U, 0x04BFU, 0x0D1BU, 0x0A97U,
	0x08DBU, 0x07D4U, 0x2178U, 0x27C0U, 0x0C8EU, 0x0921U, 0x06D6U, 0x1279U,
	0x1385U, 0x1CF7U, 0x18ABU, 0x2F0CU, 0x1116U, 0x1BF5U, 0x12ECU, 0x00D3U,
	0x1F43U, 0x27AFU, 0x244AU, 0x2CD9U, 0x06C7U, 0x0920U, 0x16A1U, 0x2693U,
	0x2000U, 0x03DAU, 0x1D67U, 0x0579U, 0x0366U, 0x0E1FU, 0x2111U, 0x0AC4U,
	0x262AU, 0x07F2U, 0x27B8U, 0x0CC0U, 0x17F4U, 0x0036U, 0x0B40U, 0x129BU,
	0x2E1DU, 0x0C02U, 0x205EU, 0x24D4U, 0x1311U, 0x1B15U, 0x0442U, 0x2736U,
	0x0A07U, 0x02C4U, 0x037DU, 0x1941U, 0x1362U, 0x2728U, 0x082AU, 0x1656U,
	0x29F7U, 0x030CU, 0x127DU, 0x120FU, 0x0856U, 0x0827U, 0x12C2U, 0x0374U,
	0x14FCU, 0x16A3U, 0x1732U, 0x10EDU, 0x199FU, 0x1D7DU, 0x1495U, 0x29A8U,
	0x109CU, 0x0CBCU, 0x171DU, 0x2A3EU, 0x1688U, 0x26FFU, 0x1FA0U, 0x1E6FU,
	0x1A90U, 0x1D43U, 0x1880U, 0x0773U, 0x2AC3U, 0x1891U, 0x2E1BU, 0x1790U,
	0x2CB9U, 0x0493U, 0x23F1U, 0x1EFDU, 0x09AFU, 0x1F22U, 0x2C49U, 0x1B96U,
	0x22CFU, 0x1A48U, 0x198EU, 0x1FB2U, 0x227CU, 0x19C3U, 0x0DD9U, 0x10FCU,
	0x1202U, 0x089DU, 0x1B57U, 0x1FAAU, 0x15B8U, 0x2896U, 0x2469U, 0x09C3U,
	0x096DU, 0x1C68U, 0x1AE1U, 0x2956U, 0x245CU, 0x24DDU, 0x0DE2U, 0x0CFEU,
	0x1767U, 0x2EC1U, 0x0D57U, 0x2FFBU, 0x266EU, 0x2F1FU, 0x10ECU, 0x1E96U,
	0x2C41U, 0x19CDU, 0x2FEFU, 0x07FCU, 0x2D5BU, 0x1CB9U, 0x2BC1U, 0x2D3EU,
	0x0E95U, 0x22EFU, 0x26FAU, 0x065BU, 0x1C00U, 0x0F5FU, 0x13BAU, 0x0ACAU,
	0x1D48U, 0x288FU, 0x02F3U, 0x0676U, 0x2F15U, 0x1358U, 0x2796U, 0x112AU,
	0x19C0U, 0x1EDAU, 0x1D49U, 0x22C8U, 0x2EFDU, 0x0DFDU, 0x29FCU, 0x162AU,
	0x2876U, 0x1325U, 0x1CF6U, 0x2243U, 0x02C6U, 0x1A6CU, 0x210EU, 0x1C19U,
	0x14FBU, 0x1C6AU, 0x2B4CU, 0x0122U, 0x1EB8U, 0x1AABU, 0x2E2EU, 0x09CDU,
	0x19B2U, 0x0FBAU, 0x16AFU, 0x05B2U, 0x1659U, 0x1682U, 0x1052U, 0x0839U,
	0x2D65U, 0x12F4U, 0x22C1U, 0x0B28U, 0x2CF6U, 0x2430U, 0x09D8U, 0x2248U,
	0x1B63U, 0x0A57U, 0x076AU, 0x1B7FU, 0x173EU, 0x2B9BU, 0x1570U, 0x1885U,
	0x23DEU, 0x2CC0U, 0x0279U, 0x273EU, 0x2D22U, 0x1601U, 0x2573U, 0x091DU,
	0x1B60U, 0x1BACU, 0x13B7U, 0x1C1FU, 0x2689U, 0x2325U, 0x0239U, 0x18F6U,
	0x2A5DU, 0x25CFU, 0x204CU, 0x2CD0U, 0x106BU, 0x07CDU, 0x0002U, 0x2473U,
	0x00A2U, 0x1826U, 0x07D0U, 0x0E41U, 0x2640U, 0x18DBU, 0x1D85U, 0x182BU,
	0x213EU, 0x26CFU, 0x15A0U, 0x233BU, 0x0E7AU, 0x2EE9U, 0x05ACU, 0x0BFBU,
	0x1576U, 0x25DCU, 0x1301U, 0x1783U, 0x1BC2U, 0x258AU, 0x11ECU, 0x27B5U,
	0x1875U, 0x16FFU, 0x0A5CU, 0x27BCU, 0x062CU, 0x288BU, 0x121EU, 0x26DDU
};

const uint16_t falcon_iGMb[FALCON_GMB_SIZE] =
{
	0x0FFBU, 0x1131U, 0x0439U, 0x04CDU, 0x09E2U, 0x177EU, 0x1F0BU, 0x14D1U,
	0x0A13U, 0x128FU, 0x1940U, 0x2DB7U, 0x1B6FU, 0x0AFCU, 0x1702U, 0x29CAU,
	0x0C25U, 0x084DU, 0x07A8U, 0x2AADU, 0x2969U, 0x28A4U, 0x105DU, 0x0753U,
	0x16D7U, 0x2162U, 0x1207U, 0x1446U, 0x2C3CU, 0x2952U, 0x16FAU, 0x2B93U,
	0x20E1U, 0x2FF3U, 0x2967U, 0x1D16U, 0x1657U, 0x0DF1U, 0x175DU, 0x277CU,
	0x114AU, 0x2072U, 0x2A03U, 0x1247U, 0x2B2CU, 0x0602U, 0x2E51U, 0x0064U,
	0x2037U, 0x19E1U, 0x25FDU, 0x1419U, 0x0D54U, 0x1EB2U, 0x16C7U, 0x24F4U,
	0x1461U, 0x29F4U, 0x1ECAU, 0x1D52U, 0x2F8CU, 0x2C1CU, 0x17A1U, 0x004FU,
	0x000DU, 0x1B1AU, 0x22B6U, 0x154DU, 0x11EAU, 0x2CBFU, 0x0B57U, 0x1244U,
	0x2673U, 0x1DC5U, 0x2276U, 0x2395U, 0x0823U, 0x213BU, 0x21EDU, 0x0C26U,
	0x1B67U, 0x0CC5U, 0x0557U, 0x18FDU, 0x2813U, 0x20F3U, 0x291FU, 0x2D27U,
	0x2B56U, 0x08A3U, 0x0710U, 0x1C97U, 0x0030U, 0x254BU, 0x0A00U, 0x04CCU,
	0x24DEU, 0x2A23U, 0x2E18U, 0x071CU, 0x2C8EU, 0x2306U, 0x180FU, 0x0BC4U,
	0x17DDU, 0x0AECU, 0x089BU, 0x0674U, 0x02C7U, 0x1B5CU, 0x041DU, 0x230DU,
	0x147CU, 0x05EDU, 0x246AU, 0x2C05U, 0x0384U, 0x0F30U, 0x2B7DU, 0x29F0U,
	0x1355U, 0x1DC0U, 0x26F6U, 0x128AU, 0x281EU, 0x007EU, 0x0B69U, 0x1A40U,
	0x19EBU, 0x198FU, 0x062EU, 0x1304U, 0x002AU, 0x02A1U, 0x08C0U, 0x1C33U,
	0x0510U, 0x2ED5U, 0x1DFBU, 0x2182U, 0x2EADU, 0x03DDU, 0x292DU, 0x1E07U,
	0x1BADU, 0x2127U, 0x03ECU, 0x27FCU, 0x125FU, 0x00A3U, 0x23B7U, 0x11F5U,
	0x191FU, 0x2F14U, 0x0BAFU, 0x2EA2U, 0x1227U, 0x0D22U, 0x080CU, 0x2C5DU,
	0x2EEBU, 0x1A08U, 0x1617U, 0x1C39U, 0x171AU, 0x246FU, 0x0FFCU, 0x16F8U,
	0x1B14U, 0x0D4AU, 0x140DU, 0x24B2U, 0x2BDDU, 0x1484U, 0x2330U, 0x0614U,
	0x1AFCU, 0x12A5U, 0x0F0DU, 0x224CU, 0x2855U, 0x1E39U, 0x06DEU, 0x1BBFU,
	0x2C6FU, 0x2FF1U, 0x219AU, 0x0CABU, 0x1988U, 0x1DA6U, 0x218FU, 0x2D20U,
	0x17D5U, 0x0CB5U, 0x26F1U, 0x25A8U, 0x119AU, 0x0E98U, 0x1AADU, 0x2A46U,
	0x23AAU, 0x26DCU, 0x0DEEU, 0x0855U, 0x0F3DU, 0x1796U, 0x1CA5U, 0x19D1U,
	0x0D8CU, 0x1233U, 0x0271U, 0x0A8CU, 0x1E3AU, 0x0D73U, 0x0BF4U, 0x0D3CU,
	0x0DC6U, 0x1142U, 0x2E87U, 0x1858U, 0x06C2U, 0x09FEU, 0x2864U, 0x14E0U,
	0x14A6U, 0x088EU, 0x2D2AU, 0x1837U, 0x09B2U, 0x2234U, 0x150BU, 0x1005U,
	0x1201U, 0x219DU, 0x2022U, 0x0090U, 0x1618U, 0x2200U, 0x0A3DU, 0x1530U,
	0x2A3CU, 0x0B8FU, 0x2C52U, 0x1869U, 0x06B3U, 0x1357U, 0x2544U, 0x0760U,
	0x0EB4U, 0x0027U, 0x201BU, 0x0820U, 0x09C6U, 0x05BDU, 0x2936U, 0x2205U,
	0x15E1U, 0x0445U, 0x0EC8U, 0x13B1U, 0x080AU, 0x20CFU, 0x2CB8U, 0x25A7U,
	0x080BU, 0x2696U, 0x1CEDU, 0x09C0U, 0x1EEEU, 0x2D4AU, 0x0173U, 0x1F39U,
	0x0C01U, 0x2856U, 0x0028U, 0x2714U, 0x241DU, 0x1F33U, 0x15E3U, 0x0FD3U,
	0x1ED6U, 0x02A4U, 0x2C74U, 0x1CD3U, 0x1965U, 0x1375U, 0x0A44U, 0x0DA0U,
	0x2ACCU, 0x1B6EU, 0x1A51U, 0x26CDU, 0x1BE3U, 0x091AU, 0x0F2CU, 0x1561U,
	0x1EB9U, 0x1B1DU, 0x1669U, 0x15EDU, 0x2521U, 0x2D30U, 0x2C0DU, 0x09CEU,
	0x1A21U, 0x0182U, 0x116EU, 0x0069U, 0x081CU, 0x28CBU, 0x0077U, 0x0F73U,
	0x1112U, 0x2CF1U, 0x0E58U, 0x2CAFU, 0x02EEU, 0x0CA8U, 0x0C3DU, 0x02F2U,
	0x0FADU, 0x2E99U, 0x23FAU, 0x1502U, 0x2E69U, 0x2B0AU, 0x0B02U, 0x073BU,
	0x1366U, 0x1FF5U, 0x0A80U, 0x183DU, 0x1A9EU, 0x039EU, 0x0B78U, 0x10E7U,
	0x27BFU, 0x1BB1U, 0x179FU, 0x24C2U, 0x28FCU, 0x22F6U, 0x09A8U, 0x186FU,
	0x02D8U, 0x1D91U, 0x17A8U, 0x28C0U, 0x2B1CU, 0x0994U, 0x0AFBU, 0x0ECBU,
	0x03B1U, 0x2326U, 0x04DCU, 0x226FU, 0x2B09U, 0x2BD2U, 0x1706U, 0x10E5U,
	0x121FU, 0x0EEBU, 0x2662U, 0x1B90U, 0x1A82U, 0x21DEU, 0x15A3U, 0x1E1BU,
	0x0551U, 0x2654U, 0x0B85U, 0x2C01U, 0x283DU, 0x2394U, 0x01DEU, 0x1959U,
	0x0065U, 0x0777U, 0x250BU, 0x0E18U, 0x2EDDU, 0x2928U, 0x032CU, 0x22D3U,
	0x027DU, 0x1FDFU, 0x14B3U, 0x23A8U, 0x0DB8U, 0x2062U, 0x1B9CU, 0x1EF2U,
	0x0BDCU, 0x1297U, 0x0873U, 0x0F61U, 0x0EABU, 0x2C2AU, 0x1E3BU, 0x133AU,
	0x2E9CU, 0x01A8U, 0x15A2U, 0x1854U, 0x2B7BU, 0x1E62U, 0x2EC6U, 0x0449U,
	0x0B4AU, 0x272BU, 0x0A09U, 0x08CAU, 0x0930U, 0x0335U, 0x09F6U, 0x2B08U,
	0x1E59U, 0x0088U, 0x0269U, 0x0C55U, 0x1701U, 0x2403U, 0x1AC7U, 0x0078U,
	0x1135U, 0x0721U, 0x25A3U, 0x1C2EU, 0x2815U, 0x2C81U, 0x0989U, 0x255AU,
	0x2BA8U, 0x0257U, 0x0825U, 0x2CC9U, 0x1C41U, 0x1821U, 0x12C1U, 0x26C6U,
	0x2332U, 0x11A2U, 0x24EFU, 0x2C58U, 0x2D96U, 0x181EU, 0x1F0EU, 0x2626U,
	0x1AF0U, 0x2D53U, 0x0C8DU, 0x2119U, 0x2691U, 0x0B13U, 0x28B6U, 0x0E94U,
	0x1F19U, 0x05B1U, 0x2A69U, 0x1F85U, 0x0340U, 0x065CU, 0x0D52U, 0x1324U,
	0x2A67U, 0x13F7U, 0x2547U, 0x18B5U, 0x1D07U, 0x0FF3U, 0x0C00U, 0x228FU,
	0x267DU, 0x278AU, 0x148BU, 0x2C95U, 0x199CU, 0x012FU, 0x05B9U, 0x0F1FU,
	0x1309U, 0x16B5U, 0x2721U, 0x1AF2U, 0x0CEFU, 0x173BU, 0x21BDU, 0x16DCU,
	0x0F10U, 0x03A0U, 0x1345U, 0x2152U, 0x074FU, 0x0888U, 0x15C3U, 0x16F7U,
	0x0D99U, 0x2D4DU, 0x2527U, 0x1FD9U, 0x0023U, 0x0A31U, 0x174BU, 0x1F80U,
	0x0438U, 0x2F07U, 0x20FCU, 0x0BECU, 0x0EE5U, 0x2B39U, 0x1A50U, 0x2106U,
	0x0924U, 0x1DE3U, 0x0776U, 0x29D5U, 0x0845U, 0x25A5U, 0x1902U, 0x178CU,
	0x084CU, 0x1E15U, 0x0A77U, 0x143FU, 0x187EU, 0x1D00U, 0x0A25U, 0x1A8BU,
	0x2406U, 0x2A55U, 0x0118U, 0x2187U, 0x0CC6U, 0x1A61U, 0x0932U, 0x0EC3U,
	0x17D6U, 0x127CU, 0x1726U, 0x09C1U, 0x21C0U, 0x2831U, 0x17DBU, 0x2F5FU,
	0x0B8EU, 0x2FFFU, 0x2834U, 0x1F96U, 0x0331U, 0x0FB5U, 0x0A32U, 0x05A4U,
	0x170BU, 0x2DC8U, 0x0CDCU, 0x0978U, 0x13E2U, 0x1C4AU, 0x1455U, 0x14A1U,
	0x26E4U, 0x0A8EU, 0x1A00U, 0x02DFU, 0x08C3U, 0x2D88U, 0x0341U, 0x0C23U,
	0x177CU, 0x1A91U, 0x0466U, 0x18C3U, 0x1482U, 0x2897U, 0x25AAU, 0x149EU,
	0x0DB9U, 0x2629U, 0x0BD1U, 0x030BU, 0x24D9U, 0x0D40U, 0x1D0DU, 0x029CU,
	0x27C8U, 0x1FAFU, 0x197FU, 0x19A8U, 0x2A4FU, 0x1952U, 0x2047U, 0x164FU,
	0x2634U, 0x01D3U, 0x1556U, 0x1149U, 0x2EDFU, 0x04B5U, 0x1397U, 0x1B06U,
	0x13E8U, 0x0EF3U, 0x1595U, 0x2D3BU, 0x0DBEU, 0x130BU, 0x1CDCU, 0x078BU,
	0x19D7U, 0x0605U, 0x2204U, 0x0104U, 0x0D39U, 0x12B8U, 0x1127U, 0x1641U,
	0x1ED7U, 0x086BU, 0x1CA9U, 0x00ECU, 0x298BU, 0x2D0EU, 0x0772U, 0x12B9U,
	0x2537U, 0x1C47U, 0x20A2U, 0x1401U, 0x29A6U, 0x0907U, 0x0D12U, 0x216CU,
	0x02C3U, 0x0440U, 0x1348U, 0x02A6U, 0x2805U, 0x0012U, 0x1634U, 0x03C0U,
	0x116BU, 0x1F15U, 0x00E2U, 0x0993U, 0x0006U, 0x22AAU, 0x0140U, 0x189AU,
	0x2303U, 0x221FU, 0x0B24U, 0x0BA5U, 0x06ABU, 0x1520U, 0x1399U, 0x2694U,
	0x263EU, 0x0B98U, 0x076BU, 0x1A49U, 0x1057U, 0x14AAU, 0x2764U, 0x1DFFU,
	0x1F05U, 0x2228U, 0x163EU, 0x0D85U, 0x104FU, 0x1673U, 0x15B9U, 0x0D32U,
	0x146BU, 0x03B8U, 0x10DFU, 0x2652U, 0x1104U, 0x0C10U, 0x2B6EU, 0x0348U,
	0x1871U, 0x01E6U, 0x1770U, 0x053EU, 0x288EU, 0x1781U, 0x12BEU, 0x1571U,
	0x1192U, 0x1061U, 0x0902U, 0x1979U, 0x05C3U, 0x18E4U, 0x2345U, 0x1F65U,
	0x0659U, 0x1B6CU, 0x1284U, 0x1662U, 0x1F14U, 0x18CFU, 0x195EU, 0x1B05U,
	0x2C8DU, 0x1D3FU, 0x27DAU, 0x27ABU, 0x1DF2U, 0x1D84U, 0x2CF5U, 0x060AU,
	0x19ABU, 0x27D7U, 0x08D9U, 0x1C9FU, 0x16C0U, 0x2C84U, 0x2D3DU, 0x25FAU,
	0x08CBU, 0x2BBFU, 0x14ECU, 0x1CF0U, 0x0B2DU, 0x0FA3U, 0x23FFU, 0x01E4U,
	0x1D66U, 0x24C1U, 0x2FCBU, 0x180DU, 0x2341U, 0x0849U, 0x280FU, 0x09D7U,
	0x253DU, 0x0EF0U, 0x21E2U, 0x2C9BU, 0x2A88U, 0x129AU, 0x2C27U, 0x1001U,
	0x096EU, 0x1960U, 0x26E1U, 0x293AU, 0x0328U, 0x0BB7U, 0x0852U, 0x10BEU,
	0x2F2EU, 0x1D15U, 0x140CU, 0x1EEBU, 0x00F5U, 0x1756U, 0x130AU, 0x1C7CU,
	0x1D88U, 0x292BU, 0x26E0U, 0x2373U, 0x0841U, 0x0E89U, 0x282DU, 0x2726U,
	0x256AU, 0x22E6U, 0x2B42U, 0x251AU, 0x0126U, 0x1267U, 0x0D3FU, 0x0561U,
	0x2370U, 0x27CDU, 0x11D9U, 0x2A8AU, 0x26B5U, 0x1B0BU, 0x0035U, 0x122DU,
	0x01B7U, 0x280DU, 0x1B74U, 0x27DFU, 0x2097U, 0x0475U, 0x09FCU, 0x1DB1U,
	0x1FD6U, 0x2986U, 0x21C8U, 0x2668U, 0x1F0FU, 0x2BEDU, 0x0853U, 0x1685U,
	0x2867U, 0x2635U, 0x0A9EU, 0x058BU, 0x11B3U, 0x0F04U, 0x0FE2U, 0x10C5U,
	0x2D89U, 0x2D05U, 0x2C59U, 0x10D9U, 0x1305U, 0x2F9AU, 0x064BU, 0x2A8CU,
	0x2CE1U, 0x2281U, 0x0959U, 0x000FU, 0x2A4EU, 0x138BU, 0x0011U, 0x0235U,
	0x1703U, 0x2F91U, 0x2B32U, 0x28ACU, 0x22B5U, 0x0F86U, 0x2AE5U, 0x1BDAU,
	0x16D0U, 0x28F2U, 0x2092U, 0x1793U, 0x1B34U, 0x0626U, 0x2AB8U, 0x07E4U,
	0x09A1U, 0x1FFFU, 0x0180U, 0x0A52U, 0x0AA9U, 0x1517U, 0x087FU, 0x24B4U,
	0x2ED3U, 0x1F63U, 0x1117U, 0x19D3U, 0x1392U, 0x2E24U, 0x23ABU, 0x2CA3U,
	0x0068U, 0x18CCU, 0x25ABU, 0x1A65U, 0x2F4EU, 0x15F1U, 0x2AB7U, 0x021DU,
	0x0087U, 0x0BE1U, 0x1C20U, 0x197EU, 0x13DDU, 0x2F68U, 0x034AU, 0x1021U,
	0x1E05U, 0x2B47U, 0x20EAU, 0x03F0U, 0x0AA5U, 0x2DFCU, 0x17AAU, 0x044DU,
	0x079EU, 0x20E8U, 0x1638U, 0x1ADCU, 0x2EE5U, 0x275FU, 0x14D7U, 0x039FU,
	0x06EAU, 0x0111U, 0x20B9U, 0x08DFU, 0x1469U, 0x282BU, 0x0074U, 0x2E1FU,
	0x005BU, 0x2DB3U, 0x02F5U, 0x0518U, 0x1D64U, 0x1933U, 0x1F60U, 0x1FDAU,
	0x1D20U, 0x105FU, 0x0135U, 0x090EU, 0x08F4U, 0x2899U, 0x2D77U, 0x2509U,
	0x2FCEU, 0x2962U, 0x2561U, 0x1EE8U, 0x2880U, 0x26A1U, 0x2FD4U, 0x1C0BU,
	0x0F54U, 0x0C74U, 0x016FU, 0x081DU, 0x0150U, 0x1508U, 0x15FFU, 0x2194U,
	0x120DU, 0x06EFU, 0x22A2U, 0x01C3U, 0x17DCU, 0x0525U, 0x1866U, 0x225BU,
	0x1708U, 0x1C73U, 0x0C3CU, 0x2D2CU, 0x1371U, 0x2F81U, 0x1CCBU, 0x0556U,
	0x2F62U, 0x297BU, 0x0EE1U, 0x141DU, 0x189CU, 0x0A4EU, 0x1065U, 0x058AU,
	0x2751U, 0x103CU, 0x20B5U, 0x21C4U, 0x28CDU, 0x0372U, 0x1FDEU, 0x27BDU,
	0x2623U, 0x2F9FU, 0x01CBU, 0x0B96U, 0x0C5EU, 0x0195U, 0x1388U, 0x245FU,
	0x1904U, 0x231AU, 0x060FU, 0x1FEFU, 0x0E2EU, 0x2A0EU, 0x2431U, 0x02BCU,
	0x217DU, 0x2524U, 0x19E6U, 0x2CADU, 0x2D4BU, 0x16DAU, 0x0F6EU, 0x12A7U,
	0x2EA5U, 0x05A6U, 0x1782U, 0x0D3AU, 0x2CCEU, 0x14BEU, 0x1564U, 0x0229U,
	0x2502U, 0x0A1AU, 0x0597U, 0x0AB5U, 0x01D9U, 0x2C77U, 0x1289U, 0x0344U,
	0x0FDEU, 0x29AAU, 0x1E2FU, 0x2DE8U, 0x159EU, 0x0138U, 0x10D3U, 0x10FFU,
	0x1684U, 0x21E7U, 0x20BDU, 0x1FFBU, 0x0005U, 0x1CE3U, 0x110BU, 0x0480U,
	0x152DU, 0x146FU, 0x1949U, 0x01B4U, 0x1D8FU, 0x219BU, 0x1855U, 0x2026U
};

static uint32_t falcon_mq_conv_small(int32_t x)
{
	/*
	* Reduce a small signed integer modulo q. The source integer MUST
	* be between -q/2 and +q/2.
	* If x < 0, the cast to uint32_t will set the high bit to 1.
	*/
	uint32_t y;

	y = (uint32_t)x;
	y += FALCON_Q & (uint32_t)-(int32_t)(y >> 31);

	return y;
}

static uint32_t falcon_mq_add(uint32_t x, uint32_t y)
{
	/*
	 * Addition modulo q. Operands must be in the 0..q-1 range.
	* We compute x + y - q. If the result is negative, then the
	* high bit will be set, and 'd >> 31' will be equal to 1
	* thus '-(d >> 31)' will be an all-one pattern. Otherwise,
	* it will be an all-zero pattern. In other words, this
	* implements a conditional addition of q.
	*/
	uint32_t d;

	d = x + y - FALCON_Q;
	d += FALCON_Q & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

static uint32_t falcon_mq_sub(uint32_t x, uint32_t y)
{
	/*
	* Subtraction modulo q. Operands must be in the 0..q-1 range.
	* As in falcon_mq_add(), we use a conditional addition to ensure the
	* result is in the 0..q-1 range.
	*/

	uint32_t d;

	d = x - y;
	d += FALCON_Q & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

static uint32_t falcon_mq_rshift1(uint32_t x)
{
	/*
	* Division by 2 modulo q. Operand must be in the 0..q-1 range.
	*/

	x += FALCON_Q & (uint32_t)-(int32_t)(x & 1);
	return (x >> 1);
}

static uint32_t falcon_mq_montymul(uint32_t x, uint32_t y)
{
	/*
	* Montgomery multiplication modulo q. If we set R = 2^16 mod q, then
	* this function computes: x * y / R mod q
	* Operands must be in the 0..q-1 range.
	*/

	uint32_t w;
	uint32_t z;

	/*
	 * We compute x*y + k*q with a value of k chosen so that the 16
	 * low bits of the result are 0. We can then shift the value.
	 * After the shift, result may still be larger than q, but it
	 * will be lower than 2*q, so a conditional subtraction works.
	 */

	z = x * y;
	w = ((z * FALCON_Q0I) & 0x0000FFFFUL) * FALCON_Q;

	/*
	 * When adding z and w, the result will have its low 16 bits
	 * equal to 0. Since x, y and z are lower than q, the sum will
	 * be no more than (2^15 - 1) * q + (q - 1)^2, which will
	 * fit on 29 bits.
	 */
	z = (z + w) >> 16;

	/*
	 * After the shift, analysis shows that the value will be less
	 * than 2q. We do a subtraction then conditional subtraction to
	 * ensure the result is in the expected range.
	 */
	z -= FALCON_Q;
	z += FALCON_Q & (uint32_t)-(int32_t)(z >> 31);
	return z;
}

static uint32_t falcon_mq_montysqr(uint32_t x)
{
	/*
	* Montgomery squaring (computes (x^2)/R).
	*/

	return falcon_mq_montymul(x, x);
}

static uint32_t falcon_mq_div_12289(uint32_t x, uint32_t y)
{
	/*
	* Divide x by y modulo q = 12289.
	* We invert y by computing y^(q-2) mod q.
	*
	* We use the following addition chain for exponent e = 12287:
	*
	*   e0 = 1
	*   e1 = 2 * e0 = 2
	*   e2 = e1 + e0 = 3
	*   e3 = e2 + e1 = 5
	*   e4 = 2 * e3 = 10
	*   e5 = 2 * e4 = 20
	*   e6 = 2 * e5 = 40
	*   e7 = 2 * e6 = 80
	*   e8 = 2 * e7 = 160
	*   e9 = e8 + e2 = 163
	*   e10 = e9 + e8 = 323
	*   e11 = 2 * e10 = 646
	*   e12 = 2 * e11 = 1292
	*   e13 = e12 + e9 = 1455
	*   e14 = 2 * e13 = 2910
	*   e15 = 2 * e14 = 5820
	*   e16 = e15 + e10 = 6143
	*   e17 = 2 * e16 = 12286
	*   e18 = e17 + e0 = 12287
	*
	* Additions on exponents are converted to Montgomery
	* multiplications. We define all intermediate results as so
	* many local variables, and let the C compiler work out which
	* must be kept around.
	*/

	uint32_t y0;
	uint32_t y1;
	uint32_t y2;
	uint32_t y3;
	uint32_t y4;
	uint32_t y5;
	uint32_t y6;
	uint32_t y7;
	uint32_t y8;
	uint32_t y9;
	uint32_t y10;
	uint32_t y11;
	uint32_t y12;
	uint32_t y13;
	uint32_t y14;
	uint32_t y15;
	uint32_t y16;
	uint32_t y17;
	uint32_t y18;

	y0 = falcon_mq_montymul(y, FALCON_R2);
	y1 = falcon_mq_montysqr(y0);
	y2 = falcon_mq_montymul(y1, y0);
	y3 = falcon_mq_montymul(y2, y1);
	y4 = falcon_mq_montysqr(y3);
	y5 = falcon_mq_montysqr(y4);
	y6 = falcon_mq_montysqr(y5);
	y7 = falcon_mq_montysqr(y6);
	y8 = falcon_mq_montysqr(y7);
	y9 = falcon_mq_montymul(y8, y2);
	y10 = falcon_mq_montymul(y9, y8);
	y11 = falcon_mq_montysqr(y10);
	y12 = falcon_mq_montysqr(y11);
	y13 = falcon_mq_montymul(y12, y9);
	y14 = falcon_mq_montysqr(y13);
	y15 = falcon_mq_montysqr(y14);
	y16 = falcon_mq_montymul(y15, y10);
	y17 = falcon_mq_montysqr(y16);
	y18 = falcon_mq_montymul(y17, y0);

	/*
	 * Final multiplication with x, which is not in Montgomery
	 * representation, computes the correct division result.
	 */
	return falcon_mq_montymul(y18, x);
}

static void falcon_mq_NTT(uint16_t* a, uint32_t logn)
{
	/*
	* Compute NTT on a ring element.
	*/

	size_t m;
	size_t n;
	size_t t;

	n = (size_t)1 << logn;
	t = n;

	for (m = 1; m < n; m <<= 1)
	{
		size_t ht;
		size_t i;
		size_t j1;

		ht = t >> 1;

		for (i = 0, j1 = 0; i < m; i++, j1 += t)
		{
			size_t j;
			size_t j2;
			uint32_t s;

			s = falcon_GMb[m + i];
			j2 = j1 + ht;

			for (j = j1; j < j2; ++j)
			{
				uint32_t u;
				uint32_t v;

				u = a[j];
				v = falcon_mq_montymul(a[j + ht], s);
				a[j] = (uint16_t)falcon_mq_add(u, v);
				a[j + ht] = (uint16_t)falcon_mq_sub(u, v);
			}
		}

		t = ht;
	}
}

static void falcon_mq_iNTT(uint16_t* a, uint32_t logn)
{
	/*
	* Compute the inverse NTT on a ring element, binary case.
	*/

	size_t m;
	size_t n;
	size_t t;
	uint32_t ni;

	n = (size_t)1 << logn;
	t = 1;
	m = n;

	while (m > 1)
	{
		size_t hm;
		size_t dt;
		size_t i;
		size_t j1;

		hm = m >> 1;
		dt = t << 1;

		for (i = 0, j1 = 0; i < hm; i++, j1 += dt)
		{
			size_t j;
			size_t j2;
			uint32_t s;

			j2 = j1 + t;
			s = falcon_iGMb[hm + i];

			for (j = j1; j < j2; ++j)
			{
				uint32_t u;
				uint32_t v;
				uint32_t w;

				u = a[j];
				v = a[j + t];
				a[j] = (uint16_t)falcon_mq_add(u, v);
				w = falcon_mq_sub(u, v);
				a[j + t] = (uint16_t)falcon_mq_montymul(w, s);
			}
		}

		t = dt;
		m = hm;
	}

	/*
	 * To complete the inverse NTT, we must now divide all values by
	 * n (the vector size). We thus need the inverse of n, i.e. we
	 * need to divide 1 by 2 logn times. But we also want it in
	 * Montgomery representation, i.e. we also want to multiply it
	 * by R = 2^16. In the common case, this should be a simple right
	 * shift. The loop below is generic and works also in corner cases
	 * its computation time is negligible.
	 */
	ni = FALCON_R;
	for (m = n; m > 1; m >>= 1) {
		ni = falcon_mq_rshift1(ni);
	}
	for (m = 0; m < n; m++) {
		a[m] = (uint16_t)falcon_mq_montymul(a[m], ni);
	}
}

static void falcon_mq_poly_tomonty(uint16_t* f, uint32_t logn)
{
	/*
	* Convert a polynomial (mod q) to Montgomery representation.
	*/

	size_t u;
	size_t n;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		f[u] = (uint16_t)falcon_mq_montymul(f[u], FALCON_R2);
	}
}

static void falcon_mq_poly_montymul_ntt(uint16_t* f, const uint16_t* g, uint32_t logn)
{
	/*
	* Multiply two polynomials together (NTT representation, and using
	* a Montgomery multiplication). Result f*g is written over f.
	*/

	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		f[u] = (uint16_t)falcon_mq_montymul(f[u], g[u]);
	}
}

static void falcon_mq_poly_sub(uint16_t* f, const uint16_t* g, uint32_t logn)
{
	/*
	* Subtract polynomial g from polynomial f.
	*/

	size_t n;
	size_t u;

	n = (size_t)1 << logn;

	for (u = 0; u < n; ++u)
	{
		f[u] = (uint16_t)falcon_mq_sub(f[u], g[u]);
	}
}

static void falcon_to_ntt_monty(uint16_t* h, uint32_t logn)
{
	falcon_mq_NTT(h, logn);
	falcon_mq_poly_tomonty(h, logn);
}

static int32_t falcon_verify_raw(const uint16_t* c0, const int16_t* s2, const uint16_t* h, uint32_t logn, uint8_t* tmp)
{
	uint16_t* tt;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	tt = (uint16_t *)tmp;

	/*
	 * Reduce s2 elements modulo q ([0..q-1] range).
	 */
	for (u = 0; u < n; ++u)
	{
		uint32_t w1;
		w1 = (uint32_t)s2[u];
		w1 += FALCON_Q & (uint32_t)-(int32_t)(w1 >> 31);
		tt[u] = (uint16_t)w1;
	}

	/*
	 * Compute -s1 = s2*h - c0 mod phi mod q (in tt[]).
	 */
	falcon_mq_NTT(tt, logn);
	falcon_mq_poly_montymul_ntt(tt, h, logn);
	falcon_mq_iNTT(tt, logn);
	falcon_mq_poly_sub(tt, c0, logn);

	/*
	 * Normalize -s1 elements into the [-q/2..q/2] range.
	 */
	for (u = 0; u < n; ++u)
	{
		int32_t w2;
		w2 = (int32_t)tt[u];
		w2 -= (int32_t)(FALCON_Q & (uint32_t)-(int32_t)(((FALCON_Q >> 1) - (uint32_t)w2) >> 31));
		((int16_t *)tt)[u] = (int16_t)w2;
	}

	/*
	 * Signature is valid if and only if the aggregate (-s1,s2) vector
	 * is short enough.
	 */
	return falcon_is_short((int16_t*)tt, s2, logn);
}

static int32_t falcon_compute_public(uint16_t* h, const int8_t* f, const int8_t* g, uint32_t logn, uint8_t* tmp)
{
	size_t n;
	size_t u;
	uint16_t* tt;

	n = (size_t)1 << logn;
	tt = (uint16_t*)tmp;

	for (u = 0; u < n; ++u)
	{
		tt[u] = (uint16_t)falcon_mq_conv_small(f[u]);
		h[u] = (uint16_t)falcon_mq_conv_small(g[u]);
	}

	falcon_mq_NTT(h, logn);
	falcon_mq_NTT(tt, logn);

	for (u = 0; u < n; ++u)
	{
		if (tt[u] == 0)
		{
			return 0;
		}

		h[u] = (uint16_t)falcon_mq_div_12289(h[u], tt[u]);
	}

	falcon_mq_iNTT(h, logn);

	return 1;
}

static int32_t falcon_complete_private(int8_t* G, const int8_t* f, const int8_t* g, const int8_t* F, uint32_t logn, uint8_t* tmp)
{
	size_t n;
	size_t u;
	uint16_t* t1;
	uint16_t* t2;

	n = (size_t)1 << logn;
	t1 = (uint16_t *)tmp;
	t2 = t1 + n;

	for (u = 0; u < n; ++u)
	{
		t1[u] = (uint16_t)falcon_mq_conv_small(g[u]);
		t2[u] = (uint16_t)falcon_mq_conv_small(F[u]);
	}

	falcon_mq_NTT(t1, logn);
	falcon_mq_NTT(t2, logn);
	falcon_mq_poly_tomonty(t1, logn);
	falcon_mq_poly_montymul_ntt(t1, t2, logn);

	for (u = 0; u < n; ++u)
	{
		t2[u] = (uint16_t)falcon_mq_conv_small(f[u]);
	}

	falcon_mq_NTT(t2, logn);

	for (u = 0; u < n; ++u)
	{
		if (t2[u] == 0)
		{
			return 0;
		}

		t1[u] = (uint16_t)falcon_mq_div_12289(t1[u], t2[u]);
	}

	falcon_mq_iNTT(t1, logn);

	for (u = 0; u < n; ++u)
	{
		uint32_t w;
		int32_t gi;

		w = t1[u];
		w -= (FALCON_Q & ~(uint32_t)-(int32_t)((w - (FALCON_Q >> 1)) >> 31));
		gi = *(int32_t *)&w;

		if (gi < -127 || gi > +127)
		{
			return 0;
		}

		G[u] = (int8_t)gi;
	}

	return 1;
}

/* keygen.c */

const falcon_small_prime falcon_small_primes[FALCON_SMALL_PRIME_SIZE] =
{
	{ 0x7FFFD801UL, 0x16D6AD45UL, 0x000027FFUL, }, { 0x7FFE9001UL, 0x0C9FF289UL, 0x1C190CE1UL, },
	{ 0x7FFE8801UL, 0x023ED55AUL, 0x4F3C0B19UL, }, { 0x7FFE6001UL, 0x75D72A3EUL, 0x39B5EABEUL, },
	{ 0x7FFE1801UL, 0x3F9BA03AUL, 0x07E52DEFUL, }, { 0x7FFE0001UL, 0x5FBADDFAUL, 0x23AF57B1UL, },
	{ 0x7FFDE801UL, 0x793B16F9UL, 0x3EF534A0UL, }, { 0x7FFDC801UL, 0x62928981UL, 0x191C5336UL, },
	{ 0x7FFD5801UL, 0x259F5C33UL, 0x423B9532UL, }, { 0x7FFD2801UL, 0x797EF9F7UL, 0x3E1BB69DUL, },
	{ 0x7FFD2001UL, 0x74F9FDE3UL, 0x0128A1A1UL, }, { 0x7FFC4801UL, 0x7D2CB7E7UL, 0x150EE178UL, },
	{ 0x7FFC3801UL, 0x76AE956EUL, 0x658FB9CBUL, }, { 0x7FFBF001UL, 0x1EC7B77AUL, 0x4B0996BDUL, },
	{ 0x7FFBC001UL, 0x18662794UL, 0x40F3E9D1UL, }, { 0x7FFBA001UL, 0x374CEFBFUL, 0x74013ECCUL, },
	{ 0x7FFB5801UL, 0x43C40F2BUL, 0x504A04C4UL, }, { 0x7FFA2801UL, 0x33C62F3CUL, 0x29CAECB3UL, },
	{ 0x7FF9E001UL, 0x71162EC8UL, 0x24D332C6UL, }, { 0x7FF9C001UL, 0x709517B3UL, 0x0970B86DUL, },
	{ 0x7FF96801UL, 0x017D90F7UL, 0x1F28A98FUL, }, { 0x7FF94801UL, 0x1385F58FUL, 0x02380D45UL, },
	{ 0x7FF93801UL, 0x2DAD2EC8UL, 0x438DA58CUL, }, { 0x7FF87001UL, 0x6F085652UL, 0x046708D1UL, },
	{ 0x7FF81001UL, 0x181E0AD8UL, 0x26EC492BUL, }, { 0x7FF80001UL, 0x736DE25EUL, 0x3B50ADB5UL, },
	{ 0x7FF7B001UL, 0x5CF833F0UL, 0x25D82229UL, }, { 0x7FF73801UL, 0x1930B9DCUL, 0x76519D4CUL, },
	{ 0x7FF6E001UL, 0x686106B2UL, 0x11C6C0EAUL, }, { 0x7FF6A801UL, 0x22819C5BUL, 0x1164AE0DUL, },
	{ 0x7FF64801UL, 0x42673641UL, 0x36978F72UL, }, { 0x7FF61801UL, 0x7B5B1022UL, 0x02DA4744UL, },
	{ 0x7FF5D801UL, 0x5C8E3908UL, 0x2685775FUL, }, { 0x7FF53001UL, 0x719F56C7UL, 0x5F3CFEBBUL, },
	{ 0x7FF4E801UL, 0x6E1D4FBAUL, 0x49332E08UL, }, { 0x7FF4B801UL, 0x6C689086UL, 0x461E1925UL, },
	{ 0x7FF4A001UL, 0x42A456DEUL, 0x3EE1954EUL, }, { 0x7FF49801UL, 0x031A54BEUL, 0x37A2E449UL, },
	{ 0x7FF44001UL, 0x234D2930UL, 0x53D75746UL, }, { 0x7FF3F801UL, 0x0FAF8815UL, 0x5A40888DUL, },
	{ 0x7FF36001UL, 0x28D9CFABUL, 0x16EB1503UL, }, { 0x7FF34801UL, 0x374BFDB8UL, 0x200ABF79UL, },
	{ 0x7FF33801UL, 0x03223D12UL, 0x6B41A465UL, }, { 0x7FF33001UL, 0x4C1A7B24UL, 0x50676930UL, },
	{ 0x7FF29001UL, 0x30851759UL, 0x5AB0F9B8UL, }, { 0x7FF21801UL, 0x6E121558UL, 0x4E21B5F9UL, },
	{ 0x7FF1B801UL, 0x36CC719AUL, 0x3CBD5645UL, }, { 0x7FF12001UL, 0x280B94BCUL, 0x024CB8E0UL, },
	{ 0x7FF0E001UL, 0x10EC2600UL, 0x1FBC2772UL, }, { 0x7FF0D801UL, 0x6A19541BUL, 0x356EB5EAUL, },
	{ 0x7FF06001UL, 0x138C9732UL, 0x4F264054UL, }, { 0x7FF03001UL, 0x4E1D94D5UL, 0x3923C405UL, },
	{ 0x7FF01801UL, 0x1890E4BEUL, 0x111F68D8UL, }, { 0x7FF00801UL, 0x1179AB91UL, 0x77CB7546UL, },
	{ 0x7FEFF001UL, 0x0AABD8F4UL, 0x51031180UL, }, { 0x7FEFC001UL, 0x5A70DAD0UL, 0x6AB506E0UL, },
	{ 0x7FEF9001UL, 0x604F7666UL, 0x5E76A423UL, }, { 0x7FEF8801UL, 0x3145B335UL, 0x242FEC72UL, },
	{ 0x7FEF2801UL, 0x003A3E1CUL, 0x7112ABEFUL, }, { 0x7FEEE801UL, 0x48CD3BF8UL, 0x766E045FUL, },
	{ 0x7FEEC801UL, 0x52BC7010UL, 0x32A97BF8UL, }, { 0x7FEE8001UL, 0x6B7ED155UL, 0x62AD98E4UL, },
	{ 0x7FEE2001UL, 0x3D012431UL, 0x104FE697UL, }, { 0x7FEDD801UL, 0x400CF6D8UL, 0x1BDC1087UL, },
	{ 0x7FEDB001UL, 0x319147BCUL, 0x5AD5A39EUL, }, { 0x7FEC7801UL, 0x2A7D768FUL, 0x45C9848EUL, },
	{ 0x7FEBB801UL, 0x6933A182UL, 0x3F786CBBUL, }, { 0x7FEB8801UL, 0x25652765UL, 0x53DAAD57UL, },
	{ 0x7FEB5001UL, 0x61AC2FFDUL, 0x7C7A5B41UL, }, { 0x7FEAE001UL, 0x5A5C56FAUL, 0x292AD6DAUL, },
	{ 0x7FEAC801UL, 0x4D2F15C1UL, 0x12C89A62UL, }, { 0x7FEAC001UL, 0x73C6AA2DUL, 0x3A070861UL, },
	{ 0x7FEA9001UL, 0x6DE0FEB6UL, 0x7F17F0ECUL, }, { 0x7FEA4801UL, 0x417D742AUL, 0x157BA039UL, },
	{ 0x7FEA1801UL, 0x6064B730UL, 0x7458DEEEUL, }, { 0x7FEA0001UL, 0x6BA21081UL, 0x7BB86AA1UL, },
	{ 0x7FE9A801UL, 0x1036D105UL, 0x6880034EUL, }, { 0x7FE92801UL, 0x47EA3128UL, 0x793CCE56UL, },
	{ 0x7FE90001UL, 0x4A226A10UL, 0x45F0526CUL, }, { 0x7FE8D001UL, 0x34E19C47UL, 0x4C5FC44AUL, },
	{ 0x7FE7F001UL, 0x6268AA17UL, 0x36032EA8UL, }, { 0x7FE77801UL, 0x63BB96F0UL, 0x3E32DEBCUL, },
	{ 0x7FE76801UL, 0x491C4BEAUL, 0x536F330CUL, }, { 0x7FE6F001UL, 0x575784B5UL, 0x4EF2B0BAUL, },
	{ 0x7FE6D001UL, 0x44955B39UL, 0x2106A997UL, }, { 0x7FE69001UL, 0x0D355FAAUL, 0x1978B43FUL, },
	{ 0x7FE61801UL, 0x244B06F9UL, 0x12DECA92UL, }, { 0x7FE5A001UL, 0x660BE29EUL, 0x64644AA0UL, },
	{ 0x7FE57001UL, 0x4D9F9093UL, 0x2B34AF9CUL, }, { 0x7FE53801UL, 0x1ECC7C7DUL, 0x19BAC8B4UL, },
	{ 0x7FE4C801UL, 0x1F44635BUL, 0x608B0129UL, }, { 0x7FE4A801UL, 0x72C6B597UL, 0x3A96FFE3UL, },
	{ 0x7FE49801UL, 0x1BA4F5CEUL, 0x4D13F7FCUL, }, { 0x7FE46001UL, 0x2DFF761CUL, 0x348EDD6DUL, },
	{ 0x7FE3B801UL, 0x59FA02F1UL, 0x31E92CFCUL, }, { 0x7FE33001UL, 0x0DA7AA10UL, 0x32C31FABUL, },
	{ 0x7FE31001UL, 0x6B1A9149UL, 0x25DE8E58UL, }, { 0x7FE22001UL, 0x2AA2C722UL, 0x63F87831UL, },
	{ 0x7FE1A801UL, 0x3E0B56DAUL, 0x0BF63948UL, }, { 0x7FE13801UL, 0x389CDCCDUL, 0x6BD561D2UL, },
	{ 0x7FE0E801UL, 0x63C5BE5AUL, 0x05AE6B91UL, }, { 0x7FE01001UL, 0x3018F49CUL, 0x5527CA9FUL, },
	{ 0x7FDFC801UL, 0x5398D66CUL, 0x097F7FA6UL, }, { 0x7FDFA001UL, 0x7EA544EAUL, 0x5EB8459DUL, },
	{ 0x7FDF9801UL, 0x48919F5BUL, 0x5D134162UL, }, { 0x7FDF8801UL, 0x142AAE1AUL, 0x04FFB06FUL, },
	{ 0x7FDF5801UL, 0x52588204UL, 0x263B71F2UL, }, { 0x7FDF1001UL, 0x7049F6B6UL, 0x5B1A9987UL, },
	{ 0x7FDEF801UL, 0x4F9822B8UL, 0x03EC2D4CUL, }, { 0x7FDEE001UL, 0x7735B36AUL, 0x726D7410UL, },
	{ 0x7FDEB001UL, 0x394E93D2UL, 0x49494CE2UL, }, { 0x7FDE6801UL, 0x36449ECFUL, 0x751137EDUL, },
	{ 0x7FDDA801UL, 0x30AB388DUL, 0x1AD4C67FUL, }, { 0x7FDD7001UL, 0x558A50FAUL, 0x6AF60B84UL, },
	{ 0x7FDCF801UL, 0x01FF401FUL, 0x4BD8507EUL, }, { 0x7FDCE001UL, 0x10145309UL, 0x5246AE49UL, },
	{ 0x7FDCC801UL, 0x035C62FBUL, 0x4E7DD992UL, }, { 0x7FDB5001UL, 0x7D947125UL, 0x52F5245CUL, },
	{ 0x7FDA7001UL, 0x50576A68UL, 0x2AF21F4EUL, }, { 0x7FDA5801UL, 0x0C530C6EUL, 0x626F4773UL, },
	{ 0x7FDA2801UL, 0x7062A614UL, 0x530D4FA4UL, }, { 0x7FD98001UL, 0x6BE83A03UL, 0x01E752FBUL, },
	{ 0x7FD94001UL, 0x4DDF6C1EUL, 0x785DE580UL, }, { 0x7FD92001UL, 0x0239399AUL, 0x6DC2E49EUL, },
	{ 0x7FD88001UL, 0x5F73F3F8UL, 0x096AAC27UL, }, { 0x7FD86801UL, 0x05E2CB92UL, 0x7EDFBD64UL, },
	{ 0x7FD84801UL, 0x69A3905AUL, 0x7BBF3458UL, }, { 0x7FD80801UL, 0x53B731CAUL, 0x78FEE22CUL, },
	{ 0x7FD77801UL, 0x2FC1E672UL, 0x183CA394UL, }, { 0x7FD72801UL, 0x14D0A2A3UL, 0x5978AAE2UL, },
	{ 0x7FD70001UL, 0x5BF31308UL, 0x7C428E07UL, }, { 0x7FD6B801UL, 0x482A5924UL, 0x6818324BUL, },
	{ 0x7FD67001UL, 0x4457B5C3UL, 0x2AB46169UL, }, { 0x7FD66801UL, 0x11110650UL, 0x6CB3E231UL, },
	{ 0x7FD5F801UL, 0x5052116FUL, 0x6D78FA11UL, }, { 0x7FD5F001UL, 0x6B0843EEUL, 0x1F0317DCUL, },
	{ 0x7FD57801UL, 0x4DA23195UL, 0x32D733B9UL, }, { 0x7FD50801UL, 0x402096EEUL, 0x1E19949FUL, },
	{ 0x7FD39801UL, 0x0BD8ECF0UL, 0x6063AC96UL, }, { 0x7FD35001UL, 0x132A23BFUL, 0x0949A4CBUL, },
	{ 0x7FD34001UL, 0x3086C87CUL, 0x6C7A0B6CUL, }, { 0x7FD30801UL, 0x220AF426UL, 0x3965552FUL, },
	{ 0x7FD2D801UL, 0x681D0AC6UL, 0x0025B599UL, }, { 0x7FD2A801UL, 0x6C9096A5UL, 0x076700DBUL, },
	{ 0x7FD20001UL, 0x36B59BBAUL, 0x4B1B2F66UL, }, { 0x7FD1D801UL, 0x168E333DUL, 0x5D88B5F3UL, },
	{ 0x7FD14801UL, 0x0A71CAE4UL, 0x6CD0C31BUL, }, { 0x7FD11801UL, 0x6547FE43UL, 0x14F5B975UL, },
	{ 0x7FD08001UL, 0x3FE3AEA7UL, 0x391CC22DUL, }, { 0x7FD02801UL, 0x69178D7BUL, 0x20352426UL, },
	{ 0x7FCFF801UL, 0x3F319814UL, 0x36CFF6FFUL, }, { 0x7FCFE001UL, 0x278C72C6UL, 0x565728DCUL, },
	{ 0x7FCFD801UL, 0x3F0C62B1UL, 0x232E15F8UL, }, { 0x7FCF9001UL, 0x65A282F0UL, 0x56FB11A0UL, },
	{ 0x7FCF6001UL, 0x136BACE9UL, 0x624A0066UL, }, { 0x7FCF4801UL, 0x2C08D2EDUL, 0x1AAB3286UL, },
	{ 0x7FCE9001UL, 0x395C4262UL, 0x353ADD67UL, }, { 0x7FCE7801UL, 0x62A937F5UL, 0x35B20BBEUL, },
	{ 0x7FCD5001UL, 0x0E6FC7E6UL, 0x5D73C700UL, }, { 0x7FCD3801UL, 0x2DDC588CUL, 0x4A62DD2EUL, },
	{ 0x7FCCF001UL, 0x131A51F7UL, 0x1EBF1C2EUL, }, { 0x7FCCB001UL, 0x61B7156AUL, 0x2DF2A776UL, },
	{ 0x7FCBF001UL, 0x6902B591UL, 0x3979FDB8UL, }, { 0x7FCBD801UL, 0x1905E961UL, 0x0C3167F8UL, },
	{ 0x7FCB4801UL, 0x27B32025UL, 0x7CA26DF0UL, }, { 0x7FCB0001UL, 0x5442B40FUL, 0x5A859012UL, },
	{ 0x7FCA2001UL, 0x49CF628AUL, 0x1C5A2ECFUL, }, { 0x7FC9F001UL, 0x124D6A75UL, 0x4623CAFEUL, },
	{ 0x7FC99801UL, 0x7AF570D7UL, 0x2EE5660BUL, }, { 0x7FC95001UL, 0x4FC1FB51UL, 0x5D1EAF73UL, },
	{ 0x7FC93001UL, 0x040FE129UL, 0x05320DF3UL, }, { 0x7FC91801UL, 0x36F0CCFAUL, 0x1782FEB6UL, },
	{ 0x7FC8A001UL, 0x2AE6C441UL, 0x07FACDCCUL, }, { 0x7FC85801UL, 0x4482732AUL, 0x6EF5A343UL, },
	{ 0x7FC73801UL, 0x6E318626UL, 0x4FA0BCC1UL, }, { 0x7FC72001UL, 0x4F137316UL, 0x0623A4C4UL, },
	{ 0x7FC67801UL, 0x302A0B5FUL, 0x44F4E5D4UL, }, { 0x7FC62001UL, 0x17268163UL, 0x72D391B3UL, },
	{ 0x7FC5D001UL, 0x551BE4AEUL, 0x68B4F3F9UL, }, { 0x7FC5C001UL, 0x71F9757DUL, 0x3ACEC5BDUL, },
	{ 0x7FC57001UL, 0x79A9A1AFUL, 0x1629DF31UL, }, { 0x7FC56001UL, 0x4C49D451UL, 0x78A365CEUL, },
	{ 0x7FC54801UL, 0x2AF18C56UL, 0x52CAE0C6UL, }, { 0x7FC51001UL, 0x4D62A14FUL, 0x6745DDC6UL, },
	{ 0x7FC4B801UL, 0x5C503C68UL, 0x6CCDA922UL, }, { 0x7FC44001UL, 0x24FBB588UL, 0x4000B161UL, },
	{ 0x7FC42801UL, 0x73368BCFUL, 0x389324CDUL, }, { 0x7FC40801UL, 0x151E6D88UL, 0x6278179EUL, },
	{ 0x7FC3D801UL, 0x226ACBA0UL, 0x41635022UL, }, { 0x7FC3B001UL, 0x15548DA6UL, 0x1C8777B7UL, },
	{ 0x7FC39001UL, 0x7843C029UL, 0x5C6B3C54UL, }, { 0x7FC35001UL, 0x7BDDB53BUL, 0x6CBCEAA5UL, },
	{ 0x7FC30801UL, 0x2490E3D5UL, 0x5F9B45F6UL, }, { 0x7FC2C001UL, 0x576A76ABUL, 0x1DED5D5CUL, },
	{ 0x7FC21801UL, 0x427C1DBBUL, 0x3E43E5B7UL, }, { 0x7FC17001UL, 0x0095337DUL, 0x71654AF6UL, },
	{ 0x7FC15801UL, 0x5CD40EBCUL, 0x7A99384BUL, }, { 0x7FC12001UL, 0x26DD4967UL, 0x752D7F43UL, },
	{ 0x7FBF9001UL, 0x574BBC33UL, 0x5ACB10C5UL, }, { 0x7FBF5801UL, 0x6FD35061UL, 0x2D91FBDCUL, },
	{ 0x7FBEC801UL, 0x6042D521UL, 0x727B244CUL, }, { 0x7FBEB001UL, 0x3A79AA8FUL, 0x7A2D1281UL, },
	{ 0x7FBE0801UL, 0x6E1C688DUL, 0x2B6C9271UL, }, { 0x7FBD9001UL, 0x398D40B9UL, 0x23F1DBC0UL, },
	{ 0x7FBD7801UL, 0x7F9A4727UL, 0x007F6407UL, }, { 0x7FBD2001UL, 0x5C395EC3UL, 0x2960C9FFUL, },
	{ 0x7FBD0001UL, 0x265A67FAUL, 0x76036745UL, }, { 0x7FBCD801UL, 0x0B3DDD82UL, 0x78C4FCB6UL, },
	{ 0x7FBC8801UL, 0x62C8D81FUL, 0x167F725BUL, }, { 0x7FBC6001UL, 0x06DA458EUL, 0x3A5E40B1UL, },
	{ 0x7FBBF801UL, 0x653C016EUL, 0x5660FD60UL, }, { 0x7FBBB001UL, 0x6F072EABUL, 0x67B0F53DUL, },
	{ 0x7FBB8801UL, 0x2D19B8E9UL, 0x3B603232UL, }, { 0x7FBB3801UL, 0x374E14CAUL, 0x458CAE56UL, },
	{ 0x7FBB1001UL, 0x35F247DDUL, 0x2774EE26UL, }, { 0x7FBA5001UL, 0x02709592UL, 0x6A85EA27UL, },
	{ 0x7FB9F001UL, 0x767E40F0UL, 0x2840CCD6UL, }, { 0x7FB9D801UL, 0x2F88D77BUL, 0x4EDCDBA5UL, },
	{ 0x7FB9A001UL, 0x7B4391E6UL, 0x54278927UL, }, { 0x7FB97801UL, 0x488CA602UL, 0x55BC67BFUL, },
	{ 0x7FB90001UL, 0x186EACC7UL, 0x695F699AUL, }, { 0x7FB89801UL, 0x4764CF41UL, 0x1571DA07UL, },
	{ 0x7FB85001UL, 0x265FDF95UL, 0x1EA1FE3EUL, }, { 0x7FB83801UL, 0x66580C42UL, 0x0D0CCE91UL, },
	{ 0x7FB76001UL, 0x05532BFEUL, 0x18D623C9UL, }, { 0x7FB72001UL, 0x005AB505UL, 0x50DF54D3UL, },
	{ 0x7FB66001UL, 0x34ECEBF7UL, 0x7B9EE84AUL, }, { 0x7FB61001UL, 0x090D13C4UL, 0x623069A3UL, },
	{ 0x7FB4F001UL, 0x64D25381UL, 0x58666C08UL, }, { 0x7FB47801UL, 0x769BC5C8UL, 0x43B50D01UL, },
	{ 0x7FB46801UL, 0x392D3196UL, 0x5B4FE201UL, }, { 0x7FB46001UL, 0x1B041039UL, 0x66DA0CD2UL, },
	{ 0x7FB40001UL, 0x5B8DEDC6UL, 0x0AD9E989UL, }, { 0x7FB3F001UL, 0x21FBA06AUL, 0x29CF2D77UL, },
	{ 0x7FB2B001UL, 0x137D1A28UL, 0x188D94ABUL, }, { 0x7FB1E001UL, 0x63E0A002UL, 0x5A6E8235UL, },
	{ 0x7FB1B001UL, 0x39BA969EUL, 0x5DEB77BFUL, }, { 0x7FB16001UL, 0x528CB596UL, 0x6972238CUL, },
	{ 0x7FB12001UL, 0x75D944FAUL, 0x6D4CBC74UL, }, { 0x7FB0C001UL, 0x05AAD749UL, 0x663565C5UL, },
	{ 0x7FB0A801UL, 0x0684F84FUL, 0x3FCFD2D5UL, }, { 0x7FB09001UL, 0x0102CBFEUL, 0x29DA1159UL, },
	{ 0x7FB05801UL, 0x210317C3UL, 0x19B6192BUL, }, { 0x7FAF8001UL, 0x0E647BFFUL, 0x7A6D106EUL, },
	{ 0x7FAED801UL, 0x6B079E0EUL, 0x3D8094B0UL, }, { 0x7FADD001UL, 0x4845BD7EUL, 0x2A7C09BFUL, },
	{ 0x7FADA801UL, 0x69228418UL, 0x3102EFE3UL, }, { 0x7FAD8801UL, 0x2663A9B1UL, 0x6937DA62UL, },
	{ 0x7FAD7801UL, 0x06B73CC8UL, 0x2656873DUL, }, { 0x7FAD0001UL, 0x52B7ECFFUL, 0x4D5C3B7EUL, },
	{ 0x7FACB801UL, 0x2EB924E1UL, 0x3BA14902UL, }, { 0x7FAC8001UL, 0x35FB4F18UL, 0x6419A049UL, },
	{ 0x7FABF001UL, 0x2FABCD91UL, 0x1BE6F005UL, }, { 0x7FAB7801UL, 0x7330487CUL, 0x1AC7DBD3UL, },
	{ 0x7FAB5001UL, 0x5B0A52F8UL, 0x322DE295UL, }, { 0x7FAB4801UL, 0x4A54E063UL, 0x2C55DA2CUL, },
	{ 0x7FAAD801UL, 0x47815DF3UL, 0x17F14566UL, }, { 0x7FAAA801UL, 0x08F2D67EUL, 0x668A424CUL, },
	{ 0x7FAA2801UL, 0x4CBCBF52UL, 0x27920329UL, }, { 0x7FA9C801UL, 0x24D633C3UL, 0x6C6EEA4AUL, },
	{ 0x7FA99801UL, 0x3B945C0EUL, 0x53A174B0UL, }, { 0x7FA91001UL, 0x04E0B155UL, 0x5ACF69E5UL, },
	{ 0x7FA8D801UL, 0x07271588UL, 0x1BA14F8CUL, }, { 0x7FA8A801UL, 0x074C85BDUL, 0x7EA7D51AUL, },
	{ 0x7FA88001UL, 0x087688F9UL, 0x380C6FD1UL, }, { 0x7FA78801UL, 0x34FE6ADEUL, 0x1C7099FBUL, },
	{ 0x7FA75801UL, 0x135317C9UL, 0x42E8E15AUL, }, { 0x7FA74801UL, 0x461560EBUL, 0x51E2CD41UL, },
	{ 0x7FA71001UL, 0x42610626UL, 0x11B2232AUL, }, { 0x7FA60801UL, 0x3B13091AUL, 0x5E872013UL, },
	{ 0x7FA5F801UL, 0x53887391UL, 0x6B6F5110UL, }, { 0x7FA5D801UL, 0x5DB277CEUL, 0x2A7BDE94UL, },
	{ 0x7FA56801UL, 0x420870A0UL, 0x4A859B9DUL, }, { 0x7FA4F001UL, 0x0BB706DBUL, 0x1538256AUL, },
	{ 0x7FA4A001UL, 0x675433B2UL, 0x3F39AEA2UL, }, { 0x7FA47001UL, 0x132A7FEBUL, 0x45A2CC42UL, },
	{ 0x7FA41001UL, 0x1E262C8BUL, 0x2BB4235BUL, }, { 0x7FA29001UL, 0x3D345622UL, 0x38868E04UL, },
	{ 0x7FA20801UL, 0x385598B0UL, 0x7EF4B3AEUL, }, { 0x7FA1E801UL, 0x6F86B964UL, 0x6DE6D61AUL, },
	{ 0x7FA17001UL, 0x6ABAFD8AUL, 0x6855FCA0UL, }, { 0x7FA12801UL, 0x521131E0UL, 0x0B189650UL, },
	{ 0x7FA0F801UL, 0x7EF09DF8UL, 0x6FDBD547UL, }, { 0x7FA0C801UL, 0x7F7D08D0UL, 0x4FDEEC9CUL, },
	{ 0x7FA05801UL, 0x7337FFEBUL, 0x40D6CED5UL, }, { 0x7FA05001UL, 0x712B53EBUL, 0x6A7933F1UL, },
	{ 0x7FA02801UL, 0x3B05C8CCUL, 0x3811ABB9UL, }, { 0x7F9FC001UL, 0x53D3D865UL, 0x3B315832UL, },
	{ 0x7F9F9801UL, 0x4B4FC2A3UL, 0x113A1657UL, }, { 0x7F9E3001UL, 0x588CD393UL, 0x1E4565C2UL, },
	{ 0x7F9DE001UL, 0x705CDFC4UL, 0x128D55F1UL, }, { 0x7F9DB001UL, 0x4C97DE3FUL, 0x10BED526UL, },
	{ 0x7F9D8001UL, 0x5B0D7C06UL, 0x165A94E6UL, }, { 0x7F9D4001UL, 0x537BDBF8UL, 0x09D1122CUL, },
	{ 0x7F9D1001UL, 0x25BA3278UL, 0x3996A95BUL, }, { 0x7F9D0801UL, 0x79EDD232UL, 0x4CF168DEUL, },
	{ 0x7F9CF801UL, 0x5434F023UL, 0x165FA26DUL, }, { 0x7F9C3001UL, 0x2AE259F0UL, 0x2ECFC314UL, },
	{ 0x7F9BF001UL, 0x02B2113CUL, 0x31DCC67DUL, }, { 0x7F9BD001UL, 0x44FC2A4CUL, 0x3BB6DBD1UL, },
	{ 0x7F9B5801UL, 0x10994770UL, 0x7D181EFCUL, }, { 0x7F9A9801UL, 0x63218071UL, 0x3714915AUL, },
	{ 0x7F99D801UL, 0x2FD53387UL, 0x79E9DA9EUL, }, { 0x7F998001UL, 0x6C7C46ADUL, 0x6B4E5450UL, },
	{ 0x7F997801UL, 0x45B61931UL, 0x7D931863UL, }, { 0x7F987001UL, 0x079DCA7AUL, 0x7069E2CBUL, },
	{ 0x7F984001UL, 0x00F45C8DUL, 0x4173EEDBUL, }, { 0x7F97C801UL, 0x27B1C096UL, 0x6B17E5B7UL, },
	{ 0x7F96E001UL, 0x3E2C38B3UL, 0x167D4EDAUL, }, { 0x7F96A801UL, 0x67490343UL, 0x59ACF059UL, },
	{ 0x7F968001UL, 0x12014083UL, 0x155B1648UL, }, { 0x7F967801UL, 0x0B77B205UL, 0x71CB1EF7UL, },
	{ 0x7F965001UL, 0x183C2893UL, 0x460E1DDEUL, }, { 0x7F963001UL, 0x683D58E6UL, 0x1F4AF89FUL, },
	{ 0x7F951801UL, 0x1DC4CC16UL, 0x3D764006UL, }, { 0x7F94F801UL, 0x706A24B1UL, 0x3D63CF58UL, },
	{ 0x7F945001UL, 0x58675964UL, 0x63E9E735UL, }, { 0x7F943801UL, 0x6A1761F1UL, 0x326D4F1CUL, },
	{ 0x7F942001UL, 0x1F2B911DUL, 0x6C435D65UL, }, { 0x7F93A801UL, 0x731E4879UL, 0x4D4D7299UL, },
	{ 0x7F936801UL, 0x72488A0BUL, 0x08C6092CUL, }, { 0x7F933801UL, 0x00FB4101UL, 0x5068E6CBUL, },
	{ 0x7F932001UL, 0x6FC7D43CUL, 0x6EE4C202UL, }, { 0x7F92C001UL, 0x1B359E1DUL, 0x6AB52563UL, },
	{ 0x7F92B801UL, 0x61201AD5UL, 0x08F14E10UL, }, { 0x7F92A001UL, 0x717DB59AUL, 0x17930497UL, },
	{ 0x7F921801UL, 0x6A574588UL, 0x318E6E35UL, }, { 0x7F91A001UL, 0x0F439463UL, 0x2990B3EDUL, },
	{ 0x7F915001UL, 0x1728D96EUL, 0x0E893FAAUL, }, { 0x7F913801UL, 0x2C8D5418UL, 0x53396702UL, },
	{ 0x7F90E001UL, 0x1E3EABFFUL, 0x70FC22F1UL, }, { 0x7F904801UL, 0x2293B720UL, 0x79E8C33DUL, },
	{ 0x7F901801UL, 0x2A76C3CCUL, 0x2ECD79CBUL, }, { 0x7F8FE801UL, 0x55ED2FA0UL, 0x1FFFEEEFUL, },
	{ 0x7F8FA001UL, 0x14A7C396UL, 0x67BCECDDUL, }, { 0x7F8F3001UL, 0x10D8C9C5UL, 0x014136D6UL, },
	{ 0x7F8EF801UL, 0x53E413E4UL, 0x1311708DUL, }, { 0x7F8E8801UL, 0x608505C4UL, 0x58BAB906UL, },
	{ 0x7F8E7001UL, 0x7C89D640UL, 0x77ED1516UL, }, { 0x7F8DF001UL, 0x65A83E40UL, 0x602B26F8UL, },
	{ 0x7F8CA801UL, 0x6E0AE6E9UL, 0x4C552909UL, }, { 0x7F8C6001UL, 0x3AF9A323UL, 0x46AB85FCUL, },
	{ 0x7F8BC801UL, 0x5ABCAE62UL, 0x163839EBUL, }, { 0x7F8B6801UL, 0x643AFCB1UL, 0x0CECD76BUL, },
	{ 0x7F8B2801UL, 0x7B2901BCUL, 0x6A64EE28UL, }, { 0x7F8B2001UL, 0x1CA9C596UL, 0x5A337A13UL, },
	{ 0x7F8A9801UL, 0x328A7EB0UL, 0x3326FBDBUL, }, { 0x7F8A8001UL, 0x61DEF032UL, 0x5E5EA708UL, },
	{ 0x7F8A5001UL, 0x3811EFC5UL, 0x0AB60954UL, }, { 0x7F8A4801UL, 0x12D0074AUL, 0x397ED244UL, },
	{ 0x7F88B801UL, 0x13C490B3UL, 0x2D93E422UL, }, { 0x7F885801UL, 0x7E49442FUL, 0x4E4E7524UL, },
	{ 0x7F884001UL, 0x1EF195E3UL, 0x1EF28DA1UL, }, { 0x7F87B001UL, 0x5AFB3942UL, 0x697AFA20UL, },
	{ 0x7F875001UL, 0x20D9DC42UL, 0x30EB7F55UL, }, { 0x7F873801UL, 0x52A8E472UL, 0x1C28F9ADUL, },
	{ 0x7F86F001UL, 0x3080FE82UL, 0x542E6C53UL, }, { 0x7F86C001UL, 0x60474FF4UL, 0x5FECEE23UL, },
	{ 0x7F85D001UL, 0x509E6AC3UL, 0x6521E625UL, }, { 0x7F858001UL, 0x3E81C3C1UL, 0x5E7831E8UL, },
	{ 0x7F852801UL, 0x31D4BDF5UL, 0x38A1B2BEUL, }, { 0x7F850801UL, 0x5CE17BCDUL, 0x617B8C8AUL, },
	{ 0x7F84C001UL, 0x670552DFUL, 0x63CDAC05UL, }, { 0x7F849801UL, 0x66FAD9C6UL, 0x586BF6D0UL, },
	{ 0x7F846801UL, 0x41239EF3UL, 0x67D0380CUL, }, { 0x7F843001UL, 0x292C6B43UL, 0x4A139A75UL, },
	{ 0x7F83E801UL, 0x696D7A2CUL, 0x7E677F71UL, }, { 0x7F83A801UL, 0x67B5CEF7UL, 0x55121849UL, },
	{ 0x7F83A001UL, 0x5C383B7FUL, 0x25226562UL, }, { 0x7F834801UL, 0x5046F68DUL, 0x5FB178EEUL, },
	{ 0x7F833001UL, 0x1603583CUL, 0x3160457FUL, }, { 0x7F832801UL, 0x5D0213D7UL, 0x6A93D503UL, },
	{ 0x7F82E001UL, 0x4DAC0ED7UL, 0x237830BEUL, }, { 0x7F825801UL, 0x50BCDF96UL, 0x222DC231UL, },
	{ 0x7F823801UL, 0x03A263E8UL, 0x34CBF39BUL, }, { 0x7F81F001UL, 0x15319EADUL, 0x48C7D177UL, },
	{ 0x7F81D801UL, 0x21C3C402UL, 0x66C24064UL, }, { 0x7F80D801UL, 0x33F11569UL, 0x5FE96CEEUL, },
	{ 0x7F80C001UL, 0x581A7CE2UL, 0x43CCBFC1UL, }, { 0x7F805801UL, 0x6E8F3C9AUL, 0x398096BBUL, },
	{ 0x7F7FB801UL, 0x0C1075D7UL, 0x2D176910UL, }, { 0x7F7F8001UL, 0x536DF79DUL, 0x34BD5FCBUL, },
	{ 0x7F7F4001UL, 0x3EA5AFA6UL, 0x47A992B4UL, }, { 0x7F7F1001UL, 0x65C9AA86UL, 0x25AF228AUL, },
	{ 0x7F7EA801UL, 0x7958A753UL, 0x0DCE57C2UL, }, { 0x7F7DD001UL, 0x0AF599E4UL, 0x31F8381FUL, },
	{ 0x7F7DB801UL, 0x53A3F785UL, 0x181B92AAUL, }, { 0x7F7D5801UL, 0x12876C73UL, 0x4C77ADC1UL, },
	{ 0x7F7D3001UL, 0x4F2F3FA9UL, 0x062ADD1FUL, }, { 0x7F7D1801UL, 0x04B2E041UL, 0x3B37D04DUL, },
	{ 0x7F7D1001UL, 0x4EA8FC2BUL, 0x3EEFD269UL, }, { 0x7F7BC001UL, 0x16E88BB8UL, 0x65B29565UL, },
	{ 0x7F7BA801UL, 0x40A9C6B3UL, 0x182E2479UL, }, { 0x7F7B5001UL, 0x17E98C5CUL, 0x751C120DUL, },
	{ 0x7F7B2001UL, 0x6E4CE47CUL, 0x4A550B71UL, }, { 0x7F7B0001UL, 0x341C2D8DUL, 0x5DF0F95DUL, },
	{ 0x7F7AD801UL, 0x46C76D36UL, 0x3B383D27UL, }, { 0x7F7AB801UL, 0x6A3E2A08UL, 0x3E2E1153UL, },
	{ 0x7F7AA801UL, 0x48CE9E47UL, 0x2FB12FBBUL, }, { 0x7F7A9001UL, 0x18A4FB18UL, 0x567752CEUL, },
	{ 0x7F79E801UL, 0x2C0CEF14UL, 0x146BD610UL, }, { 0x7F795801UL, 0x50D0907CUL, 0x2818318EUL, },
	{ 0x7F792001UL, 0x2443211AUL, 0x5BB95C0CUL, }, { 0x7F78F001UL, 0x561FA372UL, 0x28F16F16UL, },
	{ 0x7F789001UL, 0x1CE40DEAUL, 0x558A87F6UL, }, { 0x7F785001UL, 0x2027843DUL, 0x4CEAD5B5UL, },
	{ 0x7F780801UL, 0x7CC8DEAEUL, 0x77DF8A56UL, }, { 0x7F77B801UL, 0x44885B6CUL, 0x4028C9BBUL, },
	{ 0x7F77A001UL, 0x321BE24EUL, 0x7DB48FB9UL, }, { 0x7F777001UL, 0x0C7F4DF3UL, 0x0BCFDEFDUL, },
	{ 0x7F774801UL, 0x75C58702UL, 0x4C1D88C0UL, }, { 0x7F76C801UL, 0x509438C8UL, 0x75D475FDUL, },
	{ 0x7F765001UL, 0x6C521E35UL, 0x75F963D5UL, }, { 0x7F75D801UL, 0x743BD0F9UL, 0x0C204708UL, },
	{ 0x7F756801UL, 0x362DC881UL, 0x25748C3DUL, }, { 0x7F756001UL, 0x0D1B44B0UL, 0x2D3596E8UL, },
	{ 0x7F750801UL, 0x4DE1F6ABUL, 0x3A444AAAUL, }, { 0x7F74A801UL, 0x11CFAB62UL, 0x777D6C97UL, },
	{ 0x7F747001UL, 0x1A501C98UL, 0x3E86807CUL, }, { 0x7F743001UL, 0x5A76BF8CUL, 0x55F749A9UL, },
	{ 0x7F73B801UL, 0x50D1901DUL, 0x622D591FUL, }, { 0x7F72E001UL, 0x1FAB325FUL, 0x681AE0DAUL, },
	{ 0x7F729001UL, 0x7136B5F2UL, 0x2E9377FCUL, }, { 0x7F726001UL, 0x6C177735UL, 0x60B583E3UL, },
	{ 0x7F723801UL, 0x40C209BBUL, 0x3D1E7E67UL, }, { 0x7F721801UL, 0x7723462BUL, 0x314BFBFAUL, },
	{ 0x7F71F001UL, 0x7284D8E2UL, 0x2CAF0EE5UL, }, { 0x7F70E001UL, 0x609D0394UL, 0x7EC4343FUL, },
	{ 0x7F70D001UL, 0x3164269DUL, 0x70D44E19UL, }, { 0x7F709801UL, 0x0AB1822BUL, 0x5AED61E7UL, },
	{ 0x7F703801UL, 0x24B294A3UL, 0x4B13AAEAUL, }, { 0x7F6FF801UL, 0x790394D0UL, 0x67310802UL, },
	{ 0x7F6FF001UL, 0x7C687C2CUL, 0x6107D133UL, }, { 0x7F6FC801UL, 0x078889E8UL, 0x421484D8UL, },
	{ 0x7F6F7801UL, 0x2A9E7076UL, 0x3CAD2492UL, }, { 0x7F6F3001UL, 0x64F407ADUL, 0x50928190UL, },
	{ 0x7F6D9801UL, 0x4CE035D3UL, 0x3EC4E265UL, }, { 0x7F6D1001UL, 0x0BEBA252UL, 0x4AC17695UL, },
	{ 0x7F6CC001UL, 0x381CF475UL, 0x357710E4UL, }, { 0x7F6C8001UL, 0x2CBA723EUL, 0x4A91388DUL, },
	{ 0x7F6C2001UL, 0x2F91A8EFUL, 0x15F06A90UL, }, { 0x7F6C0801UL, 0x345D8287UL, 0x3DB691B1UL, },
	{ 0x7F6BC001UL, 0x008EB00AUL, 0x44EFC3BEUL, }, { 0x7F6B9001UL, 0x5264300EUL, 0x6486DB5FUL, },
	{ 0x7F6B1801UL, 0x50324952UL, 0x64337E8BUL, }, { 0x7F6AC801UL, 0x31C001B1UL, 0x259574AFUL, },
	{ 0x7F6A5001UL, 0x621E7EE1UL, 0x70C706B3UL, }, { 0x7F698001UL, 0x2E6DBD4DUL, 0x02E3630DUL, },
	{ 0x7F697801UL, 0x672A7D73UL, 0x661F7195UL, }, { 0x7F68E801UL, 0x3004A363UL, 0x5230365FUL, },
	{ 0x7F684001UL, 0x0C2E0474UL, 0x743D28E4UL, }, { 0x7F681001UL, 0x741678BAUL, 0x59743AC1UL, },
	{ 0x7F67E801UL, 0x2AE8D7B5UL, 0x5960F0FCUL, }, { 0x7F678801UL, 0x0DBC683DUL, 0x2129BA6DUL, },
	{ 0x7F66C001UL, 0x3A631B25UL, 0x189A38E3UL, }, { 0x7F65C001UL, 0x374DBBE0UL, 0x7479C461UL, },
	{ 0x7F659001UL, 0x4A228DFFUL, 0x335231A0UL, }, { 0x7F64D001UL, 0x4FF33385UL, 0x3A735AB2UL, },
	{ 0x7F64C801UL, 0x37DFD20EUL, 0x6AE23ED5UL, }, { 0x7F63F001UL, 0x2F67CAFCUL, 0x540EC25DUL, },
	{ 0x7F63C001UL, 0x08FC5BF3UL, 0x753E094FUL, }, { 0x7F62D001UL, 0x09BC79E2UL, 0x73976437UL, },
	{ 0x7F62A801UL, 0x746195CBUL, 0x2D3C1875UL, }, { 0x7F627801UL, 0x22058B71UL, 0x0D089E7AUL, },
	{ 0x7F624801UL, 0x710CAFAAUL, 0x79EE73C9UL, }, { 0x7F623001UL, 0x155E2E92UL, 0x1EE3195BUL, },
	{ 0x7F622801UL, 0x59B4D435UL, 0x28370AA8UL, }, { 0x7F621001UL, 0x01A9E3BFUL, 0x31876312UL, },
	{ 0x7F61E801UL, 0x1A3660C9UL, 0x5CB38406UL, }, { 0x7F61D001UL, 0x2F258723UL, 0x6F8C0DFFUL, },
	{ 0x7F61B801UL, 0x19C176B2UL, 0x30632998UL, }, { 0x7F619801UL, 0x50EFEB6DUL, 0x46A1A109UL, },
	{ 0x7F618801UL, 0x1EB417BBUL, 0x66436627UL, }, { 0x7F616801UL, 0x185A5CE3UL, 0x7C50A7F1UL, },
	{ 0x7F615801UL, 0x7D09C97FUL, 0x5071AC53UL, }, { 0x7F60E001UL, 0x5CC9F772UL, 0x566CA5B3UL, },
	{ 0x7F608001UL, 0x5C2267BAUL, 0x519DEAA4UL, }, { 0x7F5FD801UL, 0x13D31CCAUL, 0x0631022AUL, },
	{ 0x7F5F9001UL, 0x59680602UL, 0x631ED193UL, }, { 0x7F5EE001UL, 0x33156771UL, 0x00484F1AUL, },
	{ 0x7F5E7001UL, 0x74297008UL, 0x220029FBUL, }, { 0x7F5E6801UL, 0x0383CF68UL, 0x5D7B1DC2UL, },
	{ 0x7F5E5001UL, 0x7ECA6523UL, 0x104EFF04UL, }, { 0x7F5DC001UL, 0x06A0EA17UL, 0x46688D9CUL, },
	{ 0x7F5D2001UL, 0x60FE42A6UL, 0x64279E13UL, }, { 0x7F5C7001UL, 0x5DDEE319UL, 0x00D5CBC3UL, },
	{ 0x7F5C1801UL, 0x00D5CAAFUL, 0x434D86CBUL, }, { 0x7F5BE001UL, 0x02233823UL, 0x6D962075UL, },
	{ 0x7F5BC801UL, 0x127DD212UL, 0x514BE4B4UL, }, { 0x7F5B7001UL, 0x601BB792UL, 0x5D019154UL, },
	{ 0x7F5AB001UL, 0x43DCBE63UL, 0x2FAF401CUL, }, { 0x7F5A0801UL, 0x23E6BA2FUL, 0x556B51CCUL, },
	{ 0x7F596001UL, 0x0ADC4AF1UL, 0x726AF09EUL, }, { 0x7F594001UL, 0x13523C3DUL, 0x09DEB7FFUL, },
	{ 0x7F592801UL, 0x0BA74B19UL, 0x0CF1AE21UL, }, { 0x7F58D001UL, 0x3EA172AEUL, 0x3801E38FUL, },
	{ 0x7F588801UL, 0x706E719DUL, 0x608E1E2CUL, }, { 0x7F581001UL, 0x24567C30UL, 0x02170D45UL, },
	{ 0x7F57F801UL, 0x287E1798UL, 0x568FB88CUL, }, { 0x7F57C001UL, 0x07AABD0FUL, 0x3129B389UL, },
	{ 0x7F573801UL, 0x012DEEC8UL, 0x5AF5AC26UL, }, { 0x7F573001UL, 0x299F7824UL, 0x5B3B7627UL, },
	{ 0x7F567001UL, 0x62756B65UL, 0x6B934205UL, }, { 0x7F55E001UL, 0x137775A5UL, 0x1415DCBAUL, },
	{ 0x7F55B001UL, 0x03C52B7AUL, 0x718B9177UL, }, { 0x7F555001UL, 0x129B6DCCUL, 0x0A434B8BUL, },
	{ 0x7F549001UL, 0x16B99811UL, 0x15FEFDDEUL, }, { 0x7F547801UL, 0x15612805UL, 0x61C0893AUL, },
	{ 0x7F544801UL, 0x1E8ED544UL, 0x048156C9UL, }, { 0x7F542001UL, 0x7CDF3672UL, 0x756D2105UL, },
	{ 0x7F53F001UL, 0x71D2F522UL, 0x200D93A3UL, }, { 0x7F537801UL, 0x4F8CA083UL, 0x5B672A03UL, },
	{ 0x7F533001UL, 0x7CF2C7C0UL, 0x6AE35C5AUL, }, { 0x7F52F801UL, 0x711739BDUL, 0x1183B3F7UL, },
	{ 0x7F52D001UL, 0x370CCEAEUL, 0x3CF47DEAUL, }, { 0x7F524001UL, 0x57501D5FUL, 0x5A4E336AUL, },
	{ 0x7F523801UL, 0x78711F60UL, 0x7AE21208UL, }, { 0x7F51F001UL, 0x11553BA7UL, 0x6C2A8899UL, },
	{ 0x7F516801UL, 0x0952B796UL, 0x4A8D0C01UL, }, { 0x7F50B801UL, 0x11BAE0E4UL, 0x437B5FCCUL, },
	{ 0x7F501801UL, 0x201CC0E8UL, 0x64A9856CUL, }, { 0x00000000UL, 0x00000000UL, 0x00000000UL, },
};

const uint16_t falcon_rev10[FALCON_REV10_SIZE] =
{
	0x0000U, 0x0200U, 0x0100U, 0x0300U, 0x0080U, 0x0280U, 0x0180U, 0x0380U,
	0x0040U, 0x0240U, 0x0140U, 0x0340U, 0x00C0U, 0x02C0U, 0x01C0U, 0x03C0U,
	0x0020U, 0x0220U, 0x0120U, 0x0320U, 0x00A0U, 0x02A0U, 0x01A0U, 0x03A0U,
	0x0060U, 0x0260U, 0x0160U, 0x0360U, 0x00E0U, 0x02E0U, 0x01E0U, 0x03E0U,
	0x0010U, 0x0210U, 0x0110U, 0x0310U, 0x0090U, 0x0290U, 0x0190U, 0x0390U,
	0x0050U, 0x0250U, 0x0150U, 0x0350U, 0x00D0U, 0x02D0U, 0x01D0U, 0x03D0U,
	0x0030U, 0x0230U, 0x0130U, 0x0330U, 0x00B0U, 0x02B0U, 0x01B0U, 0x03B0U,
	0x0070U, 0x0270U, 0x0170U, 0x0370U, 0x00F0U, 0x02F0U, 0x01F0U, 0x03F0U,
	0x0008U, 0x0208U, 0x0108U, 0x0308U, 0x0088U, 0x0288U, 0x0188U, 0x0388U,
	0x0048U, 0x0248U, 0x0148U, 0x0348U, 0x00C8U, 0x02C8U, 0x01C8U, 0x03C8U,
	0x0028U, 0x0228U, 0x0128U, 0x0328U, 0x00A8U, 0x02A8U, 0x01A8U, 0x03A8U,
	0x0068U, 0x0268U, 0x0168U, 0x0368U, 0x00E8U, 0x02E8U, 0x01E8U, 0x03E8U,
	0x0018U, 0x0218U, 0x0118U, 0x0318U, 0x0098U, 0x0298U, 0x0198U, 0x0398U,
	0x0058U, 0x0258U, 0x0158U, 0x0358U, 0x00D8U, 0x02D8U, 0x01D8U, 0x03D8U,
	0x0038U, 0x0238U, 0x0138U, 0x0338U, 0x00B8U, 0x02B8U, 0x01B8U, 0x03B8U,
	0x0078U, 0x0278U, 0x0178U, 0x0378U, 0x00F8U, 0x02F8U, 0x01F8U, 0x03F8U,
	0x0004U, 0x0204U, 0x0104U, 0x0304U, 0x0084U, 0x0284U, 0x0184U, 0x0384U,
	0x0044U, 0x0244U, 0x0144U, 0x0344U, 0x00C4U, 0x02C4U, 0x01C4U, 0x03C4U,
	0x0024U, 0x0224U, 0x0124U, 0x0324U, 0x00A4U, 0x02A4U, 0x01A4U, 0x03A4U,
	0x0064U, 0x0264U, 0x0164U, 0x0364U, 0x00E4U, 0x02E4U, 0x01E4U, 0x03E4U,
	0x0014U, 0x0214U, 0x0114U, 0x0314U, 0x0094U, 0x0294U, 0x0194U, 0x0394U,
	0x0054U, 0x0254U, 0x0154U, 0x0354U, 0x00D4U, 0x02D4U, 0x01D4U, 0x03D4U,
	0x0034U, 0x0234U, 0x0134U, 0x0334U, 0x00B4U, 0x02B4U, 0x01B4U, 0x03B4U,
	0x0074U, 0x0274U, 0x0174U, 0x0374U, 0x00F4U, 0x02F4U, 0x01F4U, 0x03F4U,
	0x000CU, 0x020CU, 0x010CU, 0x030CU, 0x008CU, 0x028CU, 0x018CU, 0x038CU,
	0x004CU, 0x024CU, 0x014CU, 0x034CU, 0x00CCU, 0x02CCU, 0x01CCU, 0x03CCU,
	0x002CU, 0x022CU, 0x012CU, 0x032CU, 0x00ACU, 0x02ACU, 0x01ACU, 0x03ACU,
	0x006CU, 0x026CU, 0x016CU, 0x036CU, 0x00ECU, 0x02ECU, 0x01ECU, 0x03ECU,
	0x001CU, 0x021CU, 0x011CU, 0x031CU, 0x009CU, 0x029CU, 0x019CU, 0x039CU,
	0x005CU, 0x025CU, 0x015CU, 0x035CU, 0x00DCU, 0x02DCU, 0x01DCU, 0x03DCU,
	0x003CU, 0x023CU, 0x013CU, 0x033CU, 0x00BCU, 0x02BCU, 0x01BCU, 0x03BCU,
	0x007CU, 0x027CU, 0x017CU, 0x037CU, 0x00FCU, 0x02FCU, 0x01FCU, 0x03FCU,
	0x0002U, 0x0202U, 0x0102U, 0x0302U, 0x0082U, 0x0282U, 0x0182U, 0x0382U,
	0x0042U, 0x0242U, 0x0142U, 0x0342U, 0x00C2U, 0x02C2U, 0x01C2U, 0x03C2U,
	0x0022U, 0x0222U, 0x0122U, 0x0322U, 0x00A2U, 0x02A2U, 0x01A2U, 0x03A2U,
	0x0062U, 0x0262U, 0x0162U, 0x0362U, 0x00E2U, 0x02E2U, 0x01E2U, 0x03E2U,
	0x0012U, 0x0212U, 0x0112U, 0x0312U, 0x0092U, 0x0292U, 0x0192U, 0x0392U,
	0x0052U, 0x0252U, 0x0152U, 0x0352U, 0x00D2U, 0x02D2U, 0x01D2U, 0x03D2U,
	0x0032U, 0x0232U, 0x0132U, 0x0332U, 0x00B2U, 0x02B2U, 0x01B2U, 0x03B2U,
	0x0072U, 0x0272U, 0x0172U, 0x0372U, 0x00F2U, 0x02F2U, 0x01F2U, 0x03F2U,
	0x000AU, 0x020AU, 0x010AU, 0x030AU, 0x008AU, 0x028AU, 0x018AU, 0x038AU,
	0x004AU, 0x024AU, 0x014AU, 0x034AU, 0x00CAU, 0x02CAU, 0x01CAU, 0x03CAU,
	0x002AU, 0x022AU, 0x012AU, 0x032AU, 0x00AAU, 0x02AAU, 0x01AAU, 0x03AAU,
	0x006AU, 0x026AU, 0x016AU, 0x036AU, 0x00EAU, 0x02EAU, 0x01EAU, 0x03EAU,
	0x001AU, 0x021AU, 0x011AU, 0x031AU, 0x009AU, 0x029AU, 0x019AU, 0x039AU,
	0x005AU, 0x025AU, 0x015AU, 0x035AU, 0x00DAU, 0x02DAU, 0x01DAU, 0x03DAU,
	0x003AU, 0x023AU, 0x013AU, 0x033AU, 0x00BAU, 0x02BAU, 0x01BAU, 0x03BAU,
	0x007AU, 0x027AU, 0x017AU, 0x037AU, 0x00FAU, 0x02FAU, 0x01FAU, 0x03FAU,
	0x0006U, 0x0206U, 0x0106U, 0x0306U, 0x0086U, 0x0286U, 0x0186U, 0x0386U,
	0x0046U, 0x0246U, 0x0146U, 0x0346U, 0x00C6U, 0x02C6U, 0x01C6U, 0x03C6U,
	0x0026U, 0x0226U, 0x0126U, 0x0326U, 0x00A6U, 0x02A6U, 0x01A6U, 0x03A6U,
	0x0066U, 0x0266U, 0x0166U, 0x0366U, 0x00E6U, 0x02E6U, 0x01E6U, 0x03E6U,
	0x0016U, 0x0216U, 0x0116U, 0x0316U, 0x0096U, 0x0296U, 0x0196U, 0x0396U,
	0x0056U, 0x0256U, 0x0156U, 0x0356U, 0x00D6U, 0x02D6U, 0x01D6U, 0x03D6U,
	0x0036U, 0x0236U, 0x0136U, 0x0336U, 0x00B6U, 0x02B6U, 0x01B6U, 0x03B6U,
	0x0076U, 0x0276U, 0x0176U, 0x0376U, 0x00F6U, 0x02F6U, 0x01F6U, 0x03F6U,
	0x000EU, 0x020EU, 0x010EU, 0x030EU, 0x008EU, 0x028EU, 0x018EU, 0x038EU,
	0x004EU, 0x024EU, 0x014EU, 0x034EU, 0x00CEU, 0x02CEU, 0x01CEU, 0x03CEU,
	0x002EU, 0x022EU, 0x012EU, 0x032EU, 0x00AEU, 0x02AEU, 0x01AEU, 0x03AEU,
	0x006EU, 0x026EU, 0x016EU, 0x036EU, 0x00EEU, 0x02EEU, 0x01EEU, 0x03EEU,
	0x001EU, 0x021EU, 0x011EU, 0x031EU, 0x009EU, 0x029EU, 0x019EU, 0x039EU,
	0x005EU, 0x025EU, 0x015EU, 0x035EU, 0x00DEU, 0x02DEU, 0x01DEU, 0x03DEU,
	0x003EU, 0x023EU, 0x013EU, 0x033EU, 0x00BEU, 0x02BEU, 0x01BEU, 0x03BEU,
	0x007EU, 0x027EU, 0x017EU, 0x037EU, 0x00FEU, 0x02FEU, 0x01FEU, 0x03FEU,
	0x0001U, 0x0201U, 0x0101U, 0x0301U, 0x0081U, 0x0281U, 0x0181U, 0x0381U,
	0x0041U, 0x0241U, 0x0141U, 0x0341U, 0x00C1U, 0x02C1U, 0x01C1U, 0x03C1U,
	0x0021U, 0x0221U, 0x0121U, 0x0321U, 0x00A1U, 0x02A1U, 0x01A1U, 0x03A1U,
	0x0061U, 0x0261U, 0x0161U, 0x0361U, 0x00E1U, 0x02E1U, 0x01E1U, 0x03E1U,
	0x0011U, 0x0211U, 0x0111U, 0x0311U, 0x0091U, 0x0291U, 0x0191U, 0x0391U,
	0x0051U, 0x0251U, 0x0151U, 0x0351U, 0x00D1U, 0x02D1U, 0x01D1U, 0x03D1U,
	0x0031U, 0x0231U, 0x0131U, 0x0331U, 0x00B1U, 0x02B1U, 0x01B1U, 0x03B1U,
	0x0071U, 0x0271U, 0x0171U, 0x0371U, 0x00F1U, 0x02F1U, 0x01F1U, 0x03F1U,
	0x0009U, 0x0209U, 0x0109U, 0x0309U, 0x0089U, 0x0289U, 0x0189U, 0x0389U,
	0x0049U, 0x0249U, 0x0149U, 0x0349U, 0x00C9U, 0x02C9U, 0x01C9U, 0x03C9U,
	0x0029U, 0x0229U, 0x0129U, 0x0329U, 0x00A9U, 0x02A9U, 0x01A9U, 0x03A9U,
	0x0069U, 0x0269U, 0x0169U, 0x0369U, 0x00E9U, 0x02E9U, 0x01E9U, 0x03E9U,
	0x0019U, 0x0219U, 0x0119U, 0x0319U, 0x0099U, 0x0299U, 0x0199U, 0x0399U,
	0x0059U, 0x0259U, 0x0159U, 0x0359U, 0x00D9U, 0x02D9U, 0x01D9U, 0x03D9U,
	0x0039U, 0x0239U, 0x0139U, 0x0339U, 0x00B9U, 0x02B9U, 0x01B9U, 0x03B9U,
	0x0079U, 0x0279U, 0x0179U, 0x0379U, 0x00F9U, 0x02F9U, 0x01F9U, 0x03F9U,
	0x0005U, 0x0205U, 0x0105U, 0x0305U, 0x0085U, 0x0285U, 0x0185U, 0x0385U,
	0x0045U, 0x0245U, 0x0145U, 0x0345U, 0x00C5U, 0x02C5U, 0x01C5U, 0x03C5U,
	0x0025U, 0x0225U, 0x0125U, 0x0325U, 0x00A5U, 0x02A5U, 0x01A5U, 0x03A5U,
	0x0065U, 0x0265U, 0x0165U, 0x0365U, 0x00E5U, 0x02E5U, 0x01E5U, 0x03E5U,
	0x0015U, 0x0215U, 0x0115U, 0x0315U, 0x0095U, 0x0295U, 0x0195U, 0x0395U,
	0x0055U, 0x0255U, 0x0155U, 0x0355U, 0x00D5U, 0x02D5U, 0x01D5U, 0x03D5U,
	0x0035U, 0x0235U, 0x0135U, 0x0335U, 0x00B5U, 0x02B5U, 0x01B5U, 0x03B5U,
	0x0075U, 0x0275U, 0x0175U, 0x0375U, 0x00F5U, 0x02F5U, 0x01F5U, 0x03F5U,
	0x000DU, 0x020DU, 0x010DU, 0x030DU, 0x008DU, 0x028DU, 0x018DU, 0x038DU,
	0x004DU, 0x024DU, 0x014DU, 0x034DU, 0x00CDU, 0x02CDU, 0x01CDU, 0x03CDU,
	0x002DU, 0x022DU, 0x012DU, 0x032DU, 0x00ADU, 0x02ADU, 0x01ADU, 0x03ADU,
	0x006DU, 0x026DU, 0x016DU, 0x036DU, 0x00EDU, 0x02EDU, 0x01EDU, 0x03EDU,
	0x001DU, 0x021DU, 0x011DU, 0x031DU, 0x009DU, 0x029DU, 0x019DU, 0x039DU,
	0x005DU, 0x025DU, 0x015DU, 0x035DU, 0x00DDU, 0x02DDU, 0x01DDU, 0x03DDU,
	0x003DU, 0x023DU, 0x013DU, 0x033DU, 0x00BDU, 0x02BDU, 0x01BDU, 0x03BDU,
	0x007DU, 0x027DU, 0x017DU, 0x037DU, 0x00FDU, 0x02FDU, 0x01FDU, 0x03FDU,
	0x0003U, 0x0203U, 0x0103U, 0x0303U, 0x0083U, 0x0283U, 0x0183U, 0x0383U,
	0x0043U, 0x0243U, 0x0143U, 0x0343U, 0x00C3U, 0x02C3U, 0x01C3U, 0x03C3U,
	0x0023U, 0x0223U, 0x0123U, 0x0323U, 0x00A3U, 0x02A3U, 0x01A3U, 0x03A3U,
	0x0063U, 0x0263U, 0x0163U, 0x0363U, 0x00E3U, 0x02E3U, 0x01E3U, 0x03E3U,
	0x0013U, 0x0213U, 0x0113U, 0x0313U, 0x0093U, 0x0293U, 0x0193U, 0x0393U,
	0x0053U, 0x0253U, 0x0153U, 0x0353U, 0x00D3U, 0x02D3U, 0x01D3U, 0x03D3U,
	0x0033U, 0x0233U, 0x0133U, 0x0333U, 0x00B3U, 0x02B3U, 0x01B3U, 0x03B3U,
	0x0073U, 0x0273U, 0x0173U, 0x0373U, 0x00F3U, 0x02F3U, 0x01F3U, 0x03F3U,
	0x000BU, 0x020BU, 0x010BU, 0x030BU, 0x008BU, 0x028BU, 0x018BU, 0x038BU,
	0x004BU, 0x024BU, 0x014BU, 0x034BU, 0x00CBU, 0x02CBU, 0x01CBU, 0x03CBU,
	0x002BU, 0x022BU, 0x012BU, 0x032BU, 0x00ABU, 0x02ABU, 0x01ABU, 0x03ABU,
	0x006BU, 0x026BU, 0x016BU, 0x036BU, 0x00EBU, 0x02EBU, 0x01EBU, 0x03EBU,
	0x001BU, 0x021BU, 0x011BU, 0x031BU, 0x009BU, 0x029BU, 0x019BU, 0x039BU,
	0x005BU, 0x025BU, 0x015BU, 0x035BU, 0x00DBU, 0x02DBU, 0x01DBU, 0x03DBU,
	0x003BU, 0x023BU, 0x013BU, 0x033BU, 0x00BBU, 0x02BBU, 0x01BBU, 0x03BBU,
	0x007BU, 0x027BU, 0x017BU, 0x037BU, 0x00FBU, 0x02FBU, 0x01FBU, 0x03FBU,
	0x0007U, 0x0207U, 0x0107U, 0x0307U, 0x0087U, 0x0287U, 0x0187U, 0x0387U,
	0x0047U, 0x0247U, 0x0147U, 0x0347U, 0x00C7U, 0x02C7U, 0x01C7U, 0x03C7U,
	0x0027U, 0x0227U, 0x0127U, 0x0327U, 0x00A7U, 0x02A7U, 0x01A7U, 0x03A7U,
	0x0067U, 0x0267U, 0x0167U, 0x0367U, 0x00E7U, 0x02E7U, 0x01E7U, 0x03E7U,
	0x0017U, 0x0217U, 0x0117U, 0x0317U, 0x0097U, 0x0297U, 0x0197U, 0x0397U,
	0x0057U, 0x0257U, 0x0157U, 0x0357U, 0x00D7U, 0x02D7U, 0x01D7U, 0x03D7U,
	0x0037U, 0x0237U, 0x0137U, 0x0337U, 0x00B7U, 0x02B7U, 0x01B7U, 0x03B7U,
	0x0077U, 0x0277U, 0x0177U, 0x0377U, 0x00F7U, 0x02F7U, 0x01F7U, 0x03F7U,
	0x000FU, 0x020FU, 0x010FU, 0x030FU, 0x008FU, 0x028FU, 0x018FU, 0x038FU,
	0x004FU, 0x024FU, 0x014FU, 0x034FU, 0x00CFU, 0x02CFU, 0x01CFU, 0x03CFU,
	0x002FU, 0x022FU, 0x012FU, 0x032FU, 0x00AFU, 0x02AFU, 0x01AFU, 0x03AFU,
	0x006FU, 0x026FU, 0x016FU, 0x036FU, 0x00EFU, 0x02EFU, 0x01EFU, 0x03EFU,
	0x001FU, 0x021FU, 0x011FU, 0x031FU, 0x009FU, 0x029FU, 0x019FU, 0x039FU,
	0x005FU, 0x025FU, 0x015FU, 0x035FU, 0x00DFU, 0x02DFU, 0x01DFU, 0x03DFU,
	0x003FU, 0x023FU, 0x013FU, 0x033FU, 0x00BFU, 0x02BFU, 0x01BFU, 0x03BFU,
	0x007FU, 0x027FU, 0x017FU, 0x037FU, 0x00FFU, 0x02FFU, 0x01FFU, 0x03FFU
};

static size_t falcon_mkn(uint32_t logn)
{
	return ((size_t)1 << logn);
}

static uint32_t falcon_modp_set(int32_t x, uint32_t p)
{
	/*
	* Reduce a small signed integer modulo a small prime. The source
	* value x MUST be such that -p < x < p.
	*/

	uint32_t w;

	w = (uint32_t)x;
	w += p & (uint32_t)-(int32_t)(w >> 31);
	return w;
}

static int32_t falcon_modp_norm(uint32_t x, uint32_t p)
{
	/*
	* Normalize a modular integer around 0.
	*/

	return (int32_t)(x - (p & (((x - ((p + 1) >> 1)) >> 31) - 1)));
}

static uint32_t falcon_modp_ninv31(uint32_t p)
{
	/*
	* Compute -1/p mod 2^31. This works for all odd integers p that fit on 31 bits.
	*/
	uint32_t y;

	y = 2 - p;
	y *= 2 - p * y;
	y *= 2 - p * y;
	y *= 2 - p * y;
	y *= 2 - p * y;

	return (uint32_t)0x7FFFFFFFUL & (uint32_t)-(int32_t)y;
}

static uint32_t falcon_modp_R(uint32_t p)
{
	/*
	* Since 2^30 < p < 2^31, we know that 2^31 mod p is simply 2^31 - p.
	*/

	return (1UL << 31) - p;
}

static uint32_t falcon_modp_add(uint32_t a, uint32_t b, uint32_t p)
{
	/*
	* Addition modulo p.
	*/

	uint32_t d;

	d = a + b - p;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

static uint32_t falcon_modp_sub(uint32_t a, uint32_t b, uint32_t p)
{
	/*
	* Subtraction modulo p.
	*/

	uint32_t d;

	d = a - b;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

static uint32_t falcon_modp_montymul(uint32_t a, uint32_t b, uint32_t p, uint32_t p0i)
{
	/*
	* Montgomery multiplication modulo p. The 'p0i' value is -1/p mod 2^31.
	* It is required that p is an odd integer.
	*/

	uint64_t w;
	uint64_t z;
	uint32_t d;

	z = (uint64_t)a * (uint64_t)b;
	w = ((z * p0i) & 0x7FFFFFFFULL) * p;
	d = (uint32_t)((z + w) >> 31) - p;
	d += p & (uint32_t)-(int32_t)(d >> 31);

	return d;
}

static uint32_t falcon_modp_R2(uint32_t p, uint32_t p0i)
{
	/*
	* Compute R2 = 2^62 mod p.
	*/

	uint32_t z;

	/*
	 * Compute z = 2^31 mod p (this is the value 1 in Montgomery
	 * representation), then double it with an addition.
	 */
	z = falcon_modp_R(p);
	z = falcon_modp_add(z, z, p);

	/*
	 * Square it five times to obtain 2^32 in Montgomery representation
	 * (i.e. 2^63 mod p).
	 */
	z = falcon_modp_montymul(z, z, p, p0i);
	z = falcon_modp_montymul(z, z, p, p0i);
	z = falcon_modp_montymul(z, z, p, p0i);
	z = falcon_modp_montymul(z, z, p, p0i);
	z = falcon_modp_montymul(z, z, p, p0i);

	/*
	 * Halve the value mod p to get 2^62.
	 */
	z = (z + (p & (uint32_t)-(int32_t)(z & 1))) >> 1;

	return z;
}

static uint32_t falcon_modp_Rx(uint32_t x, uint32_t p, uint32_t p0i, uint32_t R2)
{
	/*
	* Compute 2^(31*x) modulo p. This works for integers x up to 2^11.
	* p must be prime such that 2^30 < p < 2^31; p0i must be equal to
	* -1/p mod 2^31; R2 must be equal to 2^62 mod p.
	*/

	int32_t i;
	uint32_t r;
	uint32_t z;

	/*
	 * 2^(31*x) = (2^31)*(2^(31*(x-1))); i.e. we want the Montgomery
	 * representation of (2^31)^e mod p, where e = x-1.
	 * R2 is 2^31 in Montgomery representation.
	 */
	x--;
	r = R2;
	z = falcon_modp_R(p);

	for (i = 0; (1U << i) <= x; i++)
	{
		if ((x & (1U << i)) != 0)
		{
			z = falcon_modp_montymul(z, r, p, p0i);
		}

		r = falcon_modp_montymul(r, r, p, p0i);
	}

	return z;
}

static uint32_t falcon_modp_div(uint32_t a, uint32_t b, uint32_t p, uint32_t p0i, uint32_t R)
{
	/*
	* Division modulo p. If the divisor (b) is 0, then 0 is returned.
	* This function computes proper results only when p is prime.
	*/

	uint32_t e;
	uint32_t z;
	int32_t i;

	e = p - 2;
	z = R;

	for (i = 30; i >= 0; i--)
	{
		uint32_t z2;

		z = falcon_modp_montymul(z, z, p, p0i);
		z2 = falcon_modp_montymul(z, b, p, p0i);
		z ^= (z ^ z2) & (uint32_t)-(int32_t)((e >> i) & 1);
	}

	/*
	 * The loop above just assumed that b was in Montgomery
	 * representation, i.e. really contained b*R; under that
	 * assumption, it returns 1/b in Montgomery representation,
	 * which is R/b. But we gave it b in normal representation,
	 * so the loop really returned R/(b/R) = R^2/b.
	 *
	 * We want a/b, so we need one Montgomery multiplication with a,
	 * which also remove one of the R factors, and another such
	 * multiplication to remove the second R factor.
	 */
	z = falcon_modp_montymul(z, 1, p, p0i);

	return falcon_modp_montymul(a, z, p, p0i);
}

static void falcon_modp_mkgm2(uint32_t* restrict gm, uint32_t* restrict igm, uint32_t logn, uint32_t g, uint32_t p, uint32_t p0i)
{
	/*
	* Compute the roots for NTT and inverse NTT (binary case). Input
	* parameter g is a primitive 2048-th root of 1 modulo p (i.e. g^1024 =
	* -1 mod p). This fills gm[] and igm[] with powers of g and 1/g:
	*   gm[rev(i)] = g^i mod p
	*   igm[rev(i)] = (1/g)^i mod p
	* where rev() is the "bit reversal" function over 10 bits. It fills
	* the arrays only up to N = 2^logn values.
	*
	* The values stored in gm[] and igm[] are in Montgomery representation.
	*
	* p must be a prime such that p = 1 mod 2048.
	*/

	size_t n;
	size_t u;
	uint32_t k;
	uint32_t ig;
	uint32_t x1;
	uint32_t x2;
	uint32_t R2;

	n = (size_t)1 << logn;

	/*
	 * We want g such that g^(2N) = 1 mod p, but the provided
	 * generator has order 2048. We must square it a few times.
	 */
	R2 = falcon_modp_R2(p, p0i);
	g = falcon_modp_montymul(g, R2, p, p0i);

	for (k = logn; k < 10; ++k)
	{
		g = falcon_modp_montymul(g, g, p, p0i);
	}

	ig = falcon_modp_div(R2, g, p, p0i, falcon_modp_R(p));
	k = 10 - logn;
	x1 = x2 = falcon_modp_R(p);

	for (u = 0; u < n; ++u)
	{
		size_t v;

		v = falcon_rev10[u << k];
		gm[v] = x1;
		igm[v] = x2;
		x1 = falcon_modp_montymul(x1, g, p, p0i);
		x2 = falcon_modp_montymul(x2, ig, p, p0i);
	}
}

static void falcon_modp_NTT2_ext(uint32_t* a, size_t stride, const uint32_t* gm, uint32_t logn, uint32_t p, uint32_t p0i)
{
	/*
	* Compute the NTT over a polynomial (binary case). Polynomial elements
	* are a[0], a[stride], a[2 * stride]...
	*/

	size_t m;
	size_t n;
	size_t t;

	if (logn != 0)
	{
		n = (size_t)1 << logn;
		t = n;

		for (m = 1; m < n; m <<= 1)
		{
			size_t ht;
			size_t u;
			size_t v1;

			ht = t >> 1;

			for (u = 0, v1 = 0; u < m; u++, v1 += t)
			{
				uint32_t s;
				size_t v;
				uint32_t *r1;
				uint32_t *r2;

				s = gm[m + u];
				r1 = a + v1 * stride;
				r2 = r1 + ht * stride;

				for (v = 0; v < ht; v++, r1 += stride, r2 += stride)
				{
					uint32_t x;
					uint32_t y;

					x = *r1;
					y = falcon_modp_montymul(*r2, s, p, p0i);
					*r1 = falcon_modp_add(x, y, p);
					*r2 = falcon_modp_sub(x, y, p);
				}
			}

			t = ht;
		}
	}
}

static void falcon_modp_iNTT2_ext(uint32_t* a, size_t stride, const uint32_t* igm, uint32_t logn, uint32_t p, uint32_t p0i)
{
	/*
	* Compute the inverse NTT over a polynomial (binary case).
	*/

	size_t t;
	size_t m;
	size_t n;
	size_t k;
	uint32_t ni;
	uint32_t *r;

	if (logn != 0)
	{
		n = (size_t)1 << logn;
		t = 1;

		for (m = n; m > 1; m >>= 1)
		{
			size_t hm;
			size_t dt;
			size_t u;
			size_t v1;

			hm = m >> 1;
			dt = t << 1;

			for (u = 0, v1 = 0; u < hm; u++, v1 += dt)
			{
				uint32_t s;
				size_t v;
				uint32_t* r1;
				uint32_t* r2;

				s = igm[hm + u];
				r1 = a + v1 * stride;
				r2 = r1 + t * stride;

				for (v = 0; v < t; v++, r1 += stride, r2 += stride)
				{
					uint32_t x;
					uint32_t y;

					x = *r1;
					y = *r2;
					*r1 = falcon_modp_add(x, y, p);
					*r2 = falcon_modp_montymul(falcon_modp_sub(x, y, p), s, p, p0i);
				}
			}

			t = dt;
		}

		/*
		 * We need 1/n in Montgomery representation, i.e. R/n. Since
		 * 1 <= logn <= 10, R/n is an integer; morever, R/n <= 2^30 < p,
		 * thus a simple shift will do.
		 */
		ni = 1UL << (31 - logn);

		for (k = 0, r = a; k < n; k++, r += stride)
		{
			*r = falcon_modp_montymul(*r, ni, p, p0i);
		}
	}
}

static void falcon_modp_poly_rec_res(uint32_t* f, uint32_t logn, uint32_t p, uint32_t p0i, uint32_t R2)
{
	/*
	* Given polynomial f in NTT representation modulo p, compute f' of degree
	* less than N/2 such that f' = f0^2 - X*f1^2, where f0 and f1 are
	* polynomials of degree less than N/2 such that f = f0(X^2) + X*f1(X^2).
	*
	* The new polynomial is written "in place" over the first N/2 elements
	* of f.
	*
	* If applied logn times successively on a given polynomial, the resulting
	* degree-0 polynomial is the resultant of f and X^N+1 modulo p.
	*
	* This function applies only to the binary case; it is invoked from
	* falcon_solve_NTRU_binary_depth1().
	*/

	size_t hn;
	size_t u;

	hn = (size_t)1 << (logn - 1);

	for (u = 0; u < hn; ++u)
	{
		uint32_t w0;
		uint32_t w1;

		w0 = f[u << 1];
		w1 = f[(u << 1) + 1];
		f[u] = falcon_modp_montymul(falcon_modp_montymul(w0, w1, p, p0i), R2, p, p0i);
	}
}

static uint32_t falcon_zint_sub(uint32_t* restrict a, const uint32_t* restrict b, size_t len, uint32_t ctl)
{
	/*
	* Subtract integer b from integer a. Both integers are supposed to have
	* the same size. The carry (0 or 1) is returned. Source arrays a and b
	* MUST be distinct.
	*
	* The operation is performed as described above if ctr = 1. If
	* ctl = 0, the value a[] is unmodified, but all memory accesses are
	* still performed, and the carry is computed and returned.
	*/

	size_t u;
	uint32_t cc;
	uint32_t m;

	cc = 0;
	m = (uint32_t)-(int32_t)ctl;

	for (u = 0; u < len; ++u)
	{
		uint32_t aw;
		uint32_t w;

		aw = a[u];
		w = aw - b[u] - cc;
		cc = w >> 31;
		aw ^= ((w & 0x7FFFFFFFUL) ^ aw) & m;
		a[u] = aw;
	}

	return cc;
}

static uint32_t falcon_zint_mul_small(uint32_t* m, size_t mlen, uint32_t x)
{
	/*
	* Mutiply the provided big integer m with a small value x.
	* This function assumes that x < 2^31. The carry word is returned.
	*/

	size_t u;
	uint32_t cc;

	cc = 0;

	for (u = 0; u < mlen; ++u)
	{
		uint64_t z;

		z = (uint64_t)m[u] * (uint64_t)x + cc;
		m[u] = (uint32_t)z & 0x7FFFFFFFUL;
		cc = (uint32_t)(z >> 31);
	}

	return cc;
}

static uint32_t falcon_zint_mod_small_unsigned(const uint32_t* d, size_t dlen, uint32_t p, uint32_t p0i, uint32_t R2)
{
	/*
	* Reduce a big integer d modulo a small integer p.
	* Rules:
	*  d is uint32_t
	*  p is prime
	*  2^30 < p < 2^31
	*  p0i = -(1/p) mod 2^31
	*  R2 = 2^62 mod p
	*/

	uint32_t x;
	size_t u;

	/*
	 * Algorithm: we inject words one by one, starting with the high
	 * word. Each step is:
	 *  - multiply x by 2^31
	 *  - add new word
	 */
	x = 0;
	u = dlen;

	while (u > 0)
	{
		uint32_t w;

		--u;
		x = falcon_modp_montymul(x, R2, p, p0i);
		w = d[u] - p;
		w += p & (uint32_t)-(int32_t)(w >> 31);
		x = falcon_modp_add(x, w, p);
	}

	return x;
}

static uint32_t falcon_zint_mod_small_signed(const uint32_t* d, size_t dlen, uint32_t p, uint32_t p0i, uint32_t R2, uint32_t Rx)
{
	/*
	* Similar to falcon_zint_mod_small_unsigned(), except that d may be signed.
	* Extra parameter is Rx = 2^(31*dlen) mod p.
	*/

	uint32_t z;

	z = 0;

	if (dlen != 0)
	{
		z = falcon_zint_mod_small_unsigned(d, dlen, p, p0i, R2);
		z = falcon_modp_sub(z, Rx & (uint32_t)-(int32_t)(d[dlen - 1] >> 30), p);
	}

	return z;
}

static void falcon_zint_add_mul_small(uint32_t* restrict x, const uint32_t* restrict y, size_t len, uint32_t s)
{
	/*
	* Add y*s to x. x and y initially have length 'len' words; the new x
	* has length 'len+1' words. 's' must fit on 31 bits. x[] and y[] must
	* not overlap.
	*/

	size_t u;
	uint32_t cc;

	cc = 0;

	for (u = 0; u < len; ++u)
	{
		uint32_t xw;
		uint32_t yw;
		uint64_t z;

		xw = x[u];
		yw = y[u];
		z = (uint64_t)yw * (uint64_t)s + (uint64_t)xw + (uint64_t)cc;
		x[u] = (uint32_t)z & 0x7FFFFFFFUL;
		cc = (uint32_t)(z >> 31);
	}

	x[len] = cc;
}

static void falcon_zint_norm_zero(uint32_t* restrict x, const uint32_t* restrict p, size_t len)
{
	/*
	* Normalize a modular integer around 0: if x > p/2, then x is replaced
	* with x - p (signed encoding with two's complement); otherwise, x is
	* untouched. The two integers x and p are encoded over the same length.
	*/

	size_t u;
	uint32_t r;
	uint32_t bb;

	/*
	 * Compare x with p/2. We use the shifted version of p, and p
	 * is odd, so we really compare with (p-1)/2; we want to perform
	 * the subtraction if and only if x > (p-1)/2.
	 */
	r = 0;
	bb = 0;
	u = len;

	while (u > 0)
	{
		uint32_t cc;
		uint32_t wp;
		uint32_t wx;

		--u;

		/*
		 * Get the two words to compare in wx and wp (both over
		 * 31 bits exactly).
		 */
		wx = x[u];
		wp = (p[u] >> 1) | (bb << 30);
		bb = p[u] & 1;

		/*
		 * We set cc to -1, 0 or 1, depending on whether wp is
		 * lower than, equal to, or greater than wx.
		 */
		cc = wp - wx;
		cc = (((uint32_t)-(int32_t)cc) >> 31) | (uint32_t)-(int32_t)(cc >> 31);

		/*
		 * If r != 0 then it is either 1 or -1, and we keep its
		 * value. Otherwise, if r = 0, then we replace it with cc.
		 */
		r |= cc & ((r & 1) - 1);
	}

	/*
	 * At this point, r = -1, 0 or 1, depending on whether (p-1)/2
	 * is lower than, equal to, or greater than x. We thus want to
	 * do the subtraction only if r = -1.
	 */
	falcon_zint_sub(x, p, len, r >> 31);
}

static void falcon_zint_rebuild_CRT(uint32_t* restrict xx, size_t xlen, size_t xstride, size_t num, const falcon_small_prime* primes,
	int32_t normalize_signed, uint32_t* restrict tmp)
{
	/*
	* Rebuild integers from their RNS representation. There are 'num'
	* integers, and each consists in 'xlen' words. 'xx' points at that
	* first word of the first integer; subsequent integers are accessed
	* by adding 'xstride' repeatedly.
	*
	* The words of an integer are the RNS representation of that integer,
	* using the provided 'primes' are moduli. This function replaces
	* each integer with its multi-word value (little-endian order).
	*
	* If "normalize_signed" is non-zero, then the returned value is
	* normalized to the -m/2..m/2 interval (where m is the product of all
	* small prime moduli); two's complement is used for negative values.
	*/

	size_t u;
	uint32_t *x;

	tmp[0] = primes[0].p;

	for (u = 1; u < xlen; ++u)
	{
		/*
		 * At the entry of each loop iteration:
		 *  - the first u words of each array have been reassembled
		 *  - the first u words of tmp[] contains the
		 * product of the prime moduli processed so far.
		 *
		 * We call 'q' the product of all previous primes.
		 */
		size_t v;
		uint32_t p;
		uint32_t p0i;
		uint32_t s;
		uint32_t R2;

		p = primes[u].p;
		s = primes[u].s;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);

		for (v = 0, x = xx; v < num; v++, x += xstride)
		{
			uint32_t xp;
			uint32_t xq;
			uint32_t xr;
			/*
			 * xp = the integer x modulo the prime p for this iteration
			 * xq = (x mod q) mod p
			 */
			xp = x[u];
			xq = falcon_zint_mod_small_unsigned(x, u, p, p0i, R2);

			/*
			 * New value is (x mod q) + q * (s * (xp - xq) mod p)
			 */
			xr = falcon_modp_montymul(s, falcon_modp_sub(xp, xq, p), p, p0i);
			falcon_zint_add_mul_small(x, tmp, u, xr);
		}

		/*
		 * Update product of primes in tmp[].
		 */
		tmp[u] = falcon_zint_mul_small(tmp, u, p);
	}

	/*
	 * Normalize the reconstructed values around 0.
	 */
	if (normalize_signed != 0)
	{
		for (u = 0, x = xx; u < num; u++, x += xstride)
		{
			falcon_zint_norm_zero(x, tmp, xlen);
		}
	}
}

static void falcon_zint_negate(uint32_t* a, size_t len, uint32_t ctl)
{
	/*
	* Negate a big integer conditionally: value a is replaced with -a if
	* and only if ctl = 1. Control value ctl must be 0 or 1.
	*/

	size_t u;
	uint32_t cc;
	uint32_t m;

	/*
	 * If ctl = 1 then we flip the bits of a by XORing with
	 * 0x7FFFFFFFUL, and we add 1 to the value. If ctl = 0 then we XOR
	 * with 0 and add 0, which leaves the value unchanged.
	 */
	cc = ctl;
	m = (uint32_t)-(int32_t)ctl >> 1;

	for (u = 0; u < len; ++u)
	{
		uint32_t aw;

		aw = a[u];
		aw = (aw ^ m) + cc;
		a[u] = aw & 0x7FFFFFFFUL;
		cc = aw >> 31;
	}
}

static uint32_t falcon_zint_co_reduce(uint32_t* a, uint32_t* b, size_t len, int64_t xa, int64_t xb, int64_t ya, int64_t yb)
{
	/*
	* Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
	* The low bits are dropped (the caller should compute the coefficients
	* such that these dropped bits are all zeros). If either or both
	* yields a negative value, then the value is negated.
	*
	* Returned value is:
	*  0  both values were positive
	*  1  new a had to be negated
	*  2  new b had to be negated
	*  3  both new a and new b had to be negated
	*
	* Coefficients xa, xb, ya and yb may use the full signed 32-bit range.
	*/

	int64_t cca;
	int64_t ccb;
	size_t u;
	uint32_t nega;
	uint32_t negb;

	cca = 0;
	ccb = 0;

	for (u = 0; u < len; ++u)
	{
		uint64_t za;
		uint64_t zb;
		uint32_t wa;
		uint32_t wb;

		wa = a[u];
		wb = b[u];
		za = wa * (uint64_t)xa + wb * (uint64_t)xb + (uint64_t)cca;
		zb = wa * (uint64_t)ya + wb * (uint64_t)yb + (uint64_t)ccb;

		if (u > 0)
		{
			a[u - 1] = (uint32_t)za & 0x7FFFFFFFUL;
			b[u - 1] = (uint32_t)zb & 0x7FFFFFFFUL;
		}

		cca = *(int64_t *)&za >> 31;
		ccb = *(int64_t *)&zb >> 31;
	}

	a[len - 1] = (uint32_t)cca;
	b[len - 1] = (uint32_t)ccb;

	nega = (uint32_t)((uint64_t)cca >> 63);
	negb = (uint32_t)((uint64_t)ccb >> 63);
	falcon_zint_negate(a, len, nega);
	falcon_zint_negate(b, len, negb);

	return nega | (negb << 1);
}

static void falcon_zint_finish_mod(uint32_t* a, size_t len, const uint32_t* m, uint32_t neg)
{
	/*
	* Finish modular reduction. Rules on input parameters:
	*
	*   if neg = 1, then -m <= a < 0
	*   if neg = 0, then 0 <= a < 2*m
	*
	* If neg = 0, then the top word of a[] is allowed to use 32 bits.
	*
	* Modulus m must be odd.
	*/

	size_t u;
	uint32_t cc;
	uint32_t xm;
	uint32_t ym;

	/*
	 * First pass: compare a (assumed nonnegative) with m. Note that
	 * if the top word uses 32 bits, subtracting m must yield a
	 * value less than 2^31 since a < 2*m.
	 */
	cc = 0;

	for (u = 0; u < len; ++u)
	{
		cc = (a[u] - m[u] - cc) >> 31;
	}

	/*
	 * If neg = 1 then we must add m (regardless of cc)
	 * If neg = 0 and cc = 0 then we must subtract m
	 * If neg = 0 and cc = 1 then we must do nothing
	 *
	 * In the loop below, we conditionally subtract either m or -m
	 * from a. Word xm is a word of m (if neg = 0) or -m (if neg = 1)
	 * but if neg = 0 and cc = 1, then ym = 0 and it forces mw to 0.
	 */
	xm = (uint32_t)-(int32_t)neg >> 1;
	ym = (uint32_t)-(int32_t)(neg | (1 - cc));
	cc = neg;

	for (u = 0; u < len; ++u)
	{
		uint32_t aw;
		uint32_t mw;

		aw = a[u];
		mw = (m[u] ^ xm) & ym;
		aw = aw - mw - cc;
		a[u] = aw & 0x7FFFFFFFUL;
		cc = aw >> 31;
	}
}

static void falcon_zint_co_reduce_mod(uint32_t* a, uint32_t* b, const uint32_t* m, size_t len,
	uint32_t m0i, int64_t xa, int64_t xb, int64_t ya, int64_t yb)
{
	/*
	* Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
	* (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31.
	*/

	int64_t cca;
	int64_t ccb;
	size_t u;
	uint32_t fa;
	uint32_t fb;

	/*
	 * These are actually four combined Montgomery multiplications.
	 */
	cca = 0;
	ccb = 0;
	fa = ((a[0] * (uint32_t)xa + b[0] * (uint32_t)xb) * m0i) & 0x7FFFFFFFUL;
	fb = ((a[0] * (uint32_t)ya + b[0] * (uint32_t)yb) * m0i) & 0x7FFFFFFFUL;

	for (u = 0; u < len; ++u)
	{
		uint64_t za;
		uint64_t zb;
		uint32_t wa;
		uint32_t wb;

		wa = a[u];
		wb = b[u];
		za = wa * (uint64_t)xa + wb * (uint64_t)xb + m[u] * (uint64_t)fa + (uint64_t)cca;
		zb = wa * (uint64_t)ya + wb * (uint64_t)yb + m[u] * (uint64_t)fb + (uint64_t)ccb;

		if (u > 0)
		{
			a[u - 1] = (uint32_t)za & 0x7FFFFFFFUL;
			b[u - 1] = (uint32_t)zb & 0x7FFFFFFFUL;
		}

		cca = *(int64_t *)&za >> 31;
		ccb = *(int64_t *)&zb >> 31;
	}

	a[len - 1] = (uint32_t)cca;
	b[len - 1] = (uint32_t)ccb;

	/*
	 * At this point:
	 *   -m <= a < 2*m
	 *   -m <= b < 2*m
	 * (this is a case of Montgomery reduction)
	 * The top words of 'a' and 'b' may have a 32-th bit set.
	 * We want to add or subtract the modulus, as required.
	 */
	falcon_zint_finish_mod(a, len, m, (uint32_t)((uint64_t)cca >> 63));
	falcon_zint_finish_mod(b, len, m, (uint32_t)((uint64_t)ccb >> 63));
}

static int32_t falcon_zint_bezout(uint32_t* restrict u, uint32_t* restrict v, const uint32_t* restrict x,
	const uint32_t* restrict y, size_t len, uint32_t* restrict tmp)
{
	/*
	 * Algorithm is an extended binary GCD. We maintain 6 values
	 * a, b, u0, u1, v0 and v1 with the following invariants:
	 *
	 *  a = x*u0 - y*v0
	 *  b = x*u1 - y*v1
	 *  0 <= a <= x
	 *  0 <= b <= y
	 *  0 <= u0 < y
	 *  0 <= v0 < x
	 *  0 <= u1 <= y
	 *  0 <= v1 < x
	 *
	 * Initial values are:
	 *
	 *  a = x   u0 = 1   v0 = 0
	 *  b = y   u1 = y   v1 = x-1
	 *
	 * Each iteration reduces either a or b, and maintains the
	 * invariants. Algorithm stops when a = b, at which point their
	 * common value is GCD(a,b) and (u0,v0) (or (u1,v1)) contains
	 * the values (u,v) we want to return.
	 *
	 * The formal definition of the algorithm is a sequence of steps:
	 *
	 *  - If a is even, then:
	 *        a <- a/2
	 *        u0 <- u0/2 mod y
	 *        v0 <- v0/2 mod x
	 *
	 *  - Otherwise, if b is even, then:
	 *        b <- b/2
	 *        u1 <- u1/2 mod y
	 *        v1 <- v1/2 mod x
	 *
	 *  - Otherwise, if a > b, then:
	 *        a <- (a-b)/2
	 *        u0 <- (u0-u1)/2 mod y
	 *        v0 <- (v0-v1)/2 mod x
	 *
	 *  - Otherwise:
	 *        b <- (b-a)/2
	 *        u1 <- (u1-u0)/2 mod y
	 *        v1 <- (v1-v0)/2 mod y
	 *
	 * We can show that the operations above preserve the invariants:
	 *
	 *  - If a is even, then u0 and v0 are either both even or both
	 *    odd (since a = x*u0 - y*v0, and x and y are both odd).
	 *    If u0 and v0 are both even, then (u0,v0) <- (u0/2,v0/2).
	 *    Otherwise, (u0,v0) <- ((u0+y)/2,(v0+x)/2). Either way,
	 *    the a = x*u0 - y*v0 invariant is preserved.
	 *
	 *  - The same holds for the case where b is even.
	 *
	 *  - If a and b are odd, and a > b, then:
	 *
	 *      a-b = x*(u0-u1) - y*(v0-v1)
	 *
	 *    In that situation, if u0 < u1, then x*(u0-u1) < 0, but
	 *    a-b > 0; therefore, it must be that v0 < v1, and the
	 *    first part of the update is: (u0,v0) <- (u0-u1+y,v0-v1+x),
	 *    which preserves the invariants. Otherwise, if u0 > u1,
	 *    then u0-u1 >= 1, thus x*(u0-u1) >= x. But a <= x and
	 *    b >= 0, hence a-b <= x. It follows that, in that case,
	 *    v0-v1 >= 0. The first part of the update is then:
	 *    (u0,v0) <- (u0-u1,v0-v1), which again preserves the
	 *    invariants.
	 *
	 *    Either way, once the subtraction is done, the new value of
	 *    a, which is the difference of two odd values, is even,
	 *    and the remaining of this step is a subcase of the
	 *    first algorithm case (i.e. when a is even).
	 *
	 *  - If a and b are odd, and b > a, then the a similar
	 *    argument holds.
	 *
	 * The values a and b start at x and y, respectively. Since x
	 * and y are odd, their GCD is odd, and it is easily seen that
	 * all steps conserve the GCD (GCD(a-b,b) = GCD(a, b)
	 * GCD(a/2,b) = GCD(a,b) if GCD(a,b) is odd). Moreover, either a
	 * or b is reduced by at least one bit at each iteration, so
	 * the algorithm necessarily converges on the case a = b, at
	 * which point the common value is the GCD.
	 *
	 * In the algorithm expressed above, when a = b, the fourth case
	 * applies, and sets b = 0. Since a contains the GCD of x and y,
	 * which are both odd, a must be odd, and subsequent iterations
	 * (if any) will simply divide b by 2 repeatedly, which has no
	 * consequence. Thus, the algorithm can run for more iterations
	 * than necessary; the final GCD will be in a, and the (u,v)
	 * coefficients will be (u0,v0).
	 *
	 *
	 * The presentation above is bit-by-bit. It can be sped up by
	 * noticing that all decisions are taken based on the low bits
	 * and high bits of a and b. We can extract the two top words
	 * and low word of each of a and b, and compute reduction
	 * parameters pa, pb, qa and qb such that the new values for
	 * a and b are:
	 *    a' = (a*pa + b*pb) / (2^31)
	 *    b' = (a*qa + b*qb) / (2^31)
	 * the two divisions being exact. The coefficients are obtained
	 * just from the extracted words, and may be slightly off, requiring
	 * an optional correction: if a' < 0, then we replace pa with -pa
	 * and pb with -pb. Each such step will reduce the total length
	 * (sum of lengths of a and b) by at least 30 bits at each
	 * iteration.
	 */

	uint32_t* u0;
	uint32_t* u1;
	uint32_t* v0;
	uint32_t* v1;
	uint32_t* a;
	uint32_t* b;
	size_t j;
	uint32_t x0i;
	uint32_t y0i;
	uint32_t num;
	uint32_t rc;

	if (len == 0)
	{
		return 0;
	}

	/*
	 * u0 and v0 are the u and v result buffers; the four other
	 * values (u1, v1, a and b) are taken from tmp[].
	 */
	u0 = u;
	v0 = v;
	u1 = tmp;
	v1 = u1 + len;
	a = v1 + len;
	b = a + len;

	/*
	 * We'll need the Montgomery reduction coefficients.
	 */
	x0i = falcon_modp_ninv31(x[0]);
	y0i = falcon_modp_ninv31(y[0]);

	/*
	 * Initialize a, b, u0, u1, v0 and v1.
	 *  a = x   u0 = 1   v0 = 0
	 *  b = y   u1 = y   v1 = x-1
	 * Note that x is odd, so computing x-1 is easy.
	 */
	qsc_memutils_copy(a, x, len * sizeof(*x));
	qsc_memutils_copy(b, y, len * sizeof(*y));
	u0[0] = 1;
	qsc_memutils_clear(u0 + 1, (len - 1) * sizeof(*u0));
	qsc_memutils_clear(v0, len * sizeof(*v0));
	qsc_memutils_copy(u1, y, len * sizeof(*u1));
	qsc_memutils_copy(v1, x, len * sizeof(*v1));
	v1[0] --;

	/*
	 * Each input operand may be as large as 31*len bits, and we
	 * reduce the total length by at least 30 bits at each iteration.
	 */
	for (num = 62 * (uint32_t)len + 30; num >= 30; num -= 30)
	{
		uint64_t a_hi;
		uint64_t b_hi;
		int64_t pa;
		int64_t pb;
		int64_t qa;
		int64_t qb;
		uint32_t c0;
		uint32_t c1;
		uint32_t a0;
		uint32_t a1;
		uint32_t b0;
		uint32_t b1;
		uint32_t a_lo;
		uint32_t b_lo;
		uint32_t r;
		int32_t i;

		/*
		 * Extract the top words of a and b. If j is the highest
		 * index >= 1 such that a[j] != 0 or b[j] != 0, then we
		 * want (a[j] << 31) + a[j-1] and (b[j] << 31) + b[j-1].
		 * If a and b are down to one word each, then we use
		 * a[0] and b[0].
		 */
		c0 = (uint32_t)-1;
		c1 = (uint32_t)-1;
		a0 = 0;
		a1 = 0;
		b0 = 0;
		b1 = 0;
		j = len;

		while (j > 0)
		{
			uint32_t aw;
			uint32_t bw;

			--j;
			aw = a[j];
			bw = b[j];
			a0 ^= (a0 ^ aw) & c0;
			a1 ^= (a1 ^ aw) & c1;
			b0 ^= (b0 ^ bw) & c0;
			b1 ^= (b1 ^ bw) & c1;
			c1 = c0;
			c0 &= (((aw | bw) + 0x7FFFFFFFUL) >> 31) - 1UL;
		}

		/*
		 * If c1 = 0, then we grabbed two words for a and b.
		 * If c1 != 0 but c0 = 0, then we grabbed one word. It
		 * is not possible that c1 != 0 and c0 != 0, because that
		 * would mean that both integers are zero.
		 */
		a1 |= a0 & c1;
		a0 &= ~c1;
		b1 |= b0 & c1;
		b0 &= ~c1;
		a_hi = ((uint64_t)a0 << 31) + a1;
		b_hi = ((uint64_t)b0 << 31) + b1;
		a_lo = a[0];
		b_lo = b[0];

		/*
		 * Compute reduction factors:
		 *
		 *   a' = a*pa + b*pb
		 *   b' = a*qa + b*qb
		 *
		 * such that a' and b' are both multiple of 2^31, but are
		 * only marginally larger than a and b.
		 */
		pa = 1;
		pb = 0;
		qa = 0;
		qb = 1;

		for (i = 0; i < 31; ++i)
		{
			/*
			 * At each iteration:
			 *
			 *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
			 *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
			 *   a <- a/2 if: a is even
			 *   b <- b/2 if: a is odd, b is even
			 *
			 * We multiply a_lo and b_lo by 2 at each
			 * iteration, thus a division by 2 really is a
			 * non-multiplication by 2.
			 */
			uint32_t rt;
			uint32_t oa;
			uint32_t ob;
			uint32_t cAB;
			uint32_t cBA;
			uint32_t cA;
			uint64_t rz;

			/*
			 * rt = 1 if a_hi > b_hi, 0 otherwise.
			 */
			rz = b_hi - a_hi;
			rt = (uint32_t)((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63);

			/*
			 * cAB = 1 if b must be subtracted from a
			 * cBA = 1 if a must be subtracted from b
			 * cA = 1 if a must be divided by 2
			 *
			 * Rules:
			 *
			 *   cAB and cBA cannot both be 1.
			 *   If a is not divided by 2, b is.
			 */
			oa = (a_lo >> i) & 1;
			ob = (b_lo >> i) & 1;
			cAB = oa & ob & rt;
			cBA = oa & ob & ~rt;
			cA = cAB | (oa ^ 1);

			/*
			 * Conditional subtractions.
			 */
			a_lo -= b_lo & (uint32_t)-(int32_t)cAB;
			a_hi -= b_hi & (uint64_t)-(int64_t)cAB;
			pa -= qa & -(int64_t)cAB;
			pb -= qb & -(int64_t)cAB;
			b_lo -= a_lo & (uint32_t)-(int32_t)cBA;
			b_hi -= a_hi & (uint64_t)-(int64_t)cBA;
			qa -= pa & -(int64_t)cBA;
			qb -= pb & -(int64_t)cBA;

			/*
			 * Shifting.
			 */
			a_lo += a_lo & (cA - 1);
			pa += pa & ((int64_t)cA - 1);
			pb += pb & ((int64_t)cA - 1);
			a_hi ^= (a_hi ^ (a_hi >> 1)) & (uint64_t)-(int64_t)cA;
			b_lo += b_lo & (uint32_t)-(int32_t)cA;
			qa += qa & -(int64_t)cA;
			qb += qb & -(int64_t)cA;
			b_hi ^= (b_hi ^ (b_hi >> 1)) & ((uint64_t)cA - 1);
		}

		/*
		 * Apply the computed parameters to our values. We
		 * may have to correct pa and pb depending on the
		 * returned value of falcon_zint_co_reduce() (when a and/or b
		 * had to be negated).
		 */
		r = falcon_zint_co_reduce(a, b, len, pa, pb, qa, qb);
		pa -= (pa + pa) & -(int64_t)(r & 1);
		pb -= (pb + pb) & -(int64_t)(r & 1);
		qa -= (qa + qa) & -(int64_t)(r >> 1);
		qb -= (qb + qb) & -(int64_t)(r >> 1);
		falcon_zint_co_reduce_mod(u0, u1, y, len, y0i, pa, pb, qa, qb);
		falcon_zint_co_reduce_mod(v0, v1, x, len, x0i, pa, pb, qa, qb);
	}

	/*
	 * At that point, array a[] should contain the GCD, and the
	 * results (u,v) should already be set. We check that the GCD
	 * is indeed 1. We also check that the two operands x and y
	 * are odd.
	 */
	rc = a[0] ^ 1;

	for (j = 1; j < len; ++j)
	{
		rc |= a[j];
	}

	return (int32_t)((1 - ((rc | (uint32_t)-(int32_t)rc) >> 31)) & x[0] & y[0]);
}

static void falcon_zint_add_scaled_mul_small(uint32_t* restrict x, size_t xlen, const uint32_t* restrict y,
	size_t ylen, int32_t k, uint32_t sch, uint32_t scl)
{
	/*
	* Add k*y*2^sc to x. The result is assumed to fit in the array of
	* size xlen (truncation is applied if necessary).
	* Scale factor 'sc' is provided as sch and scl, such that:
	*   sch = sc / 31
	*   scl = sc % 31
	* xlen MUST NOT be lower than ylen.
	*
	* x[] and y[] are both signed integers, using two's complement for
	* negative values.
	*/

	size_t u;
	uint32_t ysign;
	uint32_t tw;
	int32_t cc;

	if (ylen == 0)
	{
		return;
	}

	ysign = (uint32_t)-(int32_t)(y[ylen - 1] >> 30) >> 1;
	tw = 0;
	cc = 0;

	for (u = sch; u < xlen; ++u)
	{
		uint64_t z;
		size_t v;
		uint32_t wy;
		uint32_t wys;
		uint32_t ccu;

		/*
		 * Get the next word of y (scaled).
		 */
		v = u - sch;
		wy = v < ylen ? y[v] : ysign;
		wys = ((wy << scl) & 0x7FFFFFFFUL) | tw;
		tw = wy >> (31 - scl);

		/*
		 * The expression below does not overflow.
		 */
		z = (uint64_t)((int64_t)wys * (int64_t)k + (int64_t)x[u] + cc);
		x[u] = (uint32_t)z & 0x7FFFFFFFUL;

		/*
		 * Right-shifting the signed value z would yield
		 * implementation-defined results (arithmetic shift is
		 * not guaranteed). However, we can cast to uint32_t,
		 * and get the next carry as an uint32_t word. We can
		 * then convert it back to signed by using the guaranteed
		 * fact that 'int32_t' uses two's complement with no
		 * trap representation or padding bit, and with a layout
		 * compatible with that of 'uint32_t'.
		 */
		ccu = (uint32_t)(z >> 31);
		cc = *(int32_t*)&ccu;
	}
}

static void falcon_zint_sub_scaled(uint32_t* restrict x, size_t xlen, const uint32_t* restrict y, size_t ylen, uint32_t sch, uint32_t scl)
{
	/*
	* Subtract y*2^sc from x. The result is assumed to fit in the array of
	* size xlen (truncation is applied if necessary).
	* Scale factor 'sc' is provided as sch and scl, such that:
	*   sch = sc / 31
	*   scl = sc % 31
	* xlen MUST NOT be lower than ylen.
	*
	* x[] and y[] are both signed integers, using two's complement for
	* negative values.
	*/

	size_t u;
	uint32_t tw;
	uint32_t ysign;
	uint32_t cc;

	if (ylen == 0)
	{
		return;
	}

	ysign = (uint32_t)-(int32_t)(y[ylen - 1] >> 30) >> 1;
	tw = 0;
	cc = 0;

	for (u = sch; u < xlen; ++u)
	{
		size_t v;
		uint32_t w;
		uint32_t wy;
		uint32_t wys;

		/*
		 * Get the next word of y (scaled).
		 */
		v = u - sch;
		wy = v < ylen ? y[v] : ysign;
		wys = ((wy << scl) & 0x7FFFFFFFUL) | tw;
		tw = wy >> (31 - scl);

		w = x[u] - wys - cc;
		x[u] = w & 0x7FFFFFFFUL;
		cc = w >> 31;
	}
}

static int32_t falcon_zint_one_to_plain(const uint32_t* x)
{
	/*
	* Convert a one-word signed big integer into a signed value.
	*/

	uint32_t w;

	w = x[0];
	w |= (w & 0x40000000UL) << 1;

	return *(int32_t *)&w;
}

static void falcon_poly_big_to_fp(falcon_fpr* d, const uint32_t* f, size_t flen, size_t fstride, uint32_t logn)
{
	/*
	* Convert a polynomial to floating-point values.
	*
	* Each coefficient has length flen words, and starts fstride words after
	* the previous.
	*
	* IEEE-754 binary64 values can represent values in a finite range,
	* roughly 2^(-1023) to 2^(+1023); thus, if coefficients are too large,
	* they should be "trimmed" by pointing not to the lowest word of each,
	* but upper.
	*/

	size_t n;
	size_t u;

	n = falcon_mkn(logn);

	if (flen == 0)
	{
		for (u = 0; u < n; ++u)
		{
			d[u] = falcon_fpr_zero;
		}

		return;
	}

	for (u = 0; u < n; u++, f += fstride)
	{
		falcon_fpr fsc;
		falcon_fpr x;
		size_t v;
		uint32_t cc;
		uint32_t neg;
		uint32_t xm;

		/*
		 * Get sign of the integer; if it is negative, then we
		 * will load its absolute value instead, and negate the
		 * result.
		 */
		neg = (uint32_t)-(int32_t)(f[flen - 1] >> 30);
		xm = neg >> 1;
		cc = neg & 1;
		x = falcon_fpr_zero;
		fsc = falcon_fpr_one;

		for (v = 0; v < flen; v++, fsc = falcon_fpr_mul(fsc, falcon_fpr_ptwo31))
		{
			uint32_t w;

			w = (f[v] ^ xm) + cc;
			cc = w >> 31;
			w &= 0x7FFFFFFFUL;
			w -= (w << 1) & neg;
			x = falcon_fpr_add(x, falcon_fpr_mul(falcon_fpr_of(*(int32_t *)&w), fsc));
		}

		d[u] = x;
	}
}

static int32_t falcon_poly_big_to_small(int8_t* d, const uint32_t* s, int32_t lim, uint32_t logn)
{
	/*
	* Convert a polynomial to small integers. Source values are supposed
	* to be one-word integers, signed over 31 bits. Returned value is 0
	* if any of the coefficients exceeds the provided limit (in absolute
	* value), or 1 on success.
	*
	* This is not constant-time; this is not a problem here, because on
	* any failure, the NTRU-solving process will be deemed to have failed
	* and the (f,g) polynomials will be discarded.
	*/

	size_t n;
	size_t u;

	n = falcon_mkn(logn);

	for (u = 0; u < n; ++u)
	{
		int32_t z;

		z = falcon_zint_one_to_plain(s + u);

		if (z < -lim || z > lim)
		{
			return 0;
		}

		d[u] = (int8_t)z;
	}

	return 1;
}

static void falcon_poly_sub_scaled(uint32_t* restrict F, size_t Flen, size_t Fstride, const uint32_t* restrict f,
	size_t flen, size_t fstride, const int32_t* restrict k, uint32_t sch, uint32_t scl, uint32_t logn)
{
	/*
	* Subtract k*f from F, where F, f and k are polynomials modulo X^N+1.
	* Coefficients of polynomial k are small integers (signed values in the
	* -2^31..2^31 range) scaled by 2^sc. Value sc is provided as sch = sc / 31
	* and scl = sc % 31.
	*
	* This function implements the basic quadratic multiplication algorithm,
	* which is efficient in space (no extra buffer needed) but slow at
	* high degree.
	*/

	size_t n;
	size_t u;

	n = falcon_mkn(logn);

	for (u = 0; u < n; ++u)
	{
		int32_t kf;
		size_t v;
		uint32_t* x;
		const uint32_t* y;

		kf = -k[u];
		x = F + u * Fstride;
		y = f;

		for (v = 0; v < n; v++)
		{
			falcon_zint_add_scaled_mul_small(x, Flen, y, flen, kf, sch, scl);

			if (u + v == n - 1)
			{
				x = F;
				kf = -kf;
			}
			else
			{
				x += Fstride;
			}

			y += fstride;
		}
	}
}

static void falcon_poly_sub_scaled_ntt(uint32_t* restrict F, size_t Flen, size_t Fstride, const uint32_t* restrict f,
	size_t flen, size_t fstride, const int32_t* restrict k, uint32_t sch, uint32_t scl, uint32_t logn, uint32_t* restrict tmp)
{
	/*
	* Subtract k*f from F. Coefficients of polynomial k are small integers
	* (signed values in the -2^31..2^31 range) scaled by 2^sc. This function
	* assumes that the degree is large, and integers relatively small.
	* The value sc is provided as sch = sc / 31 and scl = sc % 31.
	*/

	uint32_t* gm;
	uint32_t* igm;
	uint32_t* fk;
	uint32_t* t1;
	uint32_t* x;
	const uint32_t *y;
	const falcon_small_prime* primes;
	size_t n;
	size_t u;
	size_t tlen;

	n = falcon_mkn(logn);
	tlen = flen + 1;
	gm = tmp;
	igm = gm + falcon_mkn(logn);
	fk = igm + falcon_mkn(logn);
	t1 = fk + n * tlen;

	primes = falcon_small_primes;

	/*
	 * Compute k*f in fk[], in RNS notation.
	 */
	for (u = 0; u < tlen; ++u)
	{
		size_t v;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t Rx;

		p = primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);
		Rx = falcon_modp_Rx((uint32_t)flen, p, p0i, R2);
		falcon_modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

		for (v = 0; v < n; ++v)
		{
			t1[v] = falcon_modp_set(k[v], p);
		}

		falcon_modp_NTT2_ext(t1, 1, gm, logn, p, p0i);

		for (v = 0, y = f, x = fk + u; v < n; v++, y += fstride, x += tlen)
		{
			*x = falcon_zint_mod_small_signed(y, flen, p, p0i, R2, Rx);
		}

		falcon_modp_NTT2_ext(fk + u, tlen, gm, logn, p, p0i);

		for (v = 0, x = fk + u; v < n; v++, x += tlen)
		{
			*x = falcon_modp_montymul(falcon_modp_montymul(t1[v], *x, p, p0i), R2, p, p0i);
		}

		falcon_modp_iNTT2_ext(fk + u, tlen, igm, logn, p, p0i);
	}

	/*
	 * Rebuild k*f.
	 */
	falcon_zint_rebuild_CRT(fk, tlen, tlen, n, primes, 1, t1);

	/*
	 * Subtract k*f, scaled, from F.
	 */
	for (u = 0, x = F, y = fk; u < n; u++, x += Fstride, y += tlen)
	{
		falcon_zint_sub_scaled(x, Flen, y, tlen, sch, scl);
	}
}

static uint64_t falcon_get_rng_u64(qsc_keccak_state* kctx)
{
	/*
	* Get a random 8-byte integer from a SHAKE-based RNG. This function
	* ensures consistent interpretation of the SHAKE output so that
	* the same values will be obtained over different platforms, in case
	* a known seed is used.
	* We enforce little-endian representation.
	*/

	uint8_t tmp[8];

	qsc_keccak_incremental_squeeze(kctx, QSC_KECCAK_256_RATE, tmp, sizeof(tmp));

	return (uint64_t)tmp[0]
		| ((uint64_t)tmp[1] << 8)
		| ((uint64_t)tmp[2] << 16)
		| ((uint64_t)tmp[3] << 24)
		| ((uint64_t)tmp[4] << 32)
		| ((uint64_t)tmp[5] << 40)
		| ((uint64_t)tmp[6] << 48)
		| ((uint64_t)tmp[7] << 56);
}

const uint64_t falcon_gauss_1024_12289[FALCON_GAUS_1024_12289_SIZE] =
{
	0x11D137D82DF2AB58ULL, 0x590C40F63FF5F974ULL, 0x3898E41D85B975B7ULL,
	0x20A964EF50858FF9ULL, 0x1107D1AE973857EBULL, 0x07FE1EC29220EA37ULL,
	0x035DAFCACD37A439ULL, 0x0144D98306216D42ULL, 0x006D6BEEEAF81655ULL,
	0x0020E1A00D6FA84CULL, 0x0008CDDDCD9DDA9CULL, 0x0002192FC3DCDCB4ULL,
	0x000071DFCD3C57E9ULL, 0x00001574938D76EBULL, 0x000003974B0C33E5ULL,
	0x000000889D3DA6FEULL, 0x0000001204DDC6CBULL, 0x000000021BD3B27AULL,
	0x0000000038091F5EULL, 0x0000000005287DB0ULL, 0x00000000006BC528ULL,
	0x000000000007CBFBULL, 0x0000000000007FFCULL, 0x0000000000000746ULL,
	0x000000000000005EULL, 0x0000000000000004ULL, 0x0000000000000000ULL
};

static int32_t falcon_mkgauss(qsc_keccak_state* kctx, uint32_t logn)
{
	/*
	* Generate a random value with a Gaussian distribution centered on 0.
	* The RNG must be ready for extraction (already flipped).
	*
	* Distribution has standard deviation 1.17*sqrt(q/(2*N)). The
	* precomputed table is for N = 1024. Since the sum of two independent
	* values of standard deviation sigma has standard deviation
	* sigma*sqrt(2), then we can just generate more values and add them
	* together for lower dimensions.
	*/

	uint32_t u;
	uint32_t g;
	int32_t val;

	g = 1U << (10 - logn);
	val = 0;

	for (u = 0; u < g; ++u)
	{
		/*
		 * Each iteration generates one value with the
		 * Gaussian distribution for N = 1024.
		 *
		 * We use two random 64-bit values. First value
		 * decides on whether the generated value is 0, and,
		 * if not, the sign of the value. Second random 64-bit
		 * word is used to generate the non-zero value.
		 *
		 * For constant-time code we have to read the complete
		 * table. This has negligible cost, compared with the
		 * remainder of the keygen process (solving the NTRU
		 * equation).
		 */
		uint64_t r;
		uint32_t f;
		uint32_t v;
		uint32_t k;
		uint32_t neg;

		/*
		 * First value:
		 *  - flag 'neg' is randomly selected to be 0 or 1.
		 *  - flag 'f' is set to 1 if the generated value is zero,
		 *    or set to 0 otherwise.
		 */
		r = falcon_get_rng_u64(kctx);
		neg = (uint32_t)(r >> 63);
		r &= ~(1ULL << 63);
		f = (uint32_t)((r - falcon_gauss_1024_12289[0]) >> 63);

		/*
		 * We produce a new random 63-bit integer r, and go over
		 * the array, starting at index 1. We store in v the
		 * index of the first array element which is not greater
		 * than r, unless the flag f was already 1.
		 */
		v = 0;
		r = falcon_get_rng_u64(kctx);
		r &= ~(1ULL << 63);

		for (k = 1; k < (sizeof(falcon_gauss_1024_12289) / sizeof(falcon_gauss_1024_12289[0])); ++k)
		{
			uint32_t t;

			t = (uint32_t)((r - falcon_gauss_1024_12289[k]) >> 63) ^ 1;
			v |= k & (uint32_t)-(int32_t)(t & (f ^ 1));
			f |= t;
		}

		/*
		 * We apply the sign ('neg' flag). If the value is zero,
		 * the sign has no effect.
		 */
		v = (v ^ (uint32_t)-(int32_t)neg) + neg;

		/*
		 * Generated value is added to val.
		 */
		val += *(int32_t *)&v;
	}

	return val;
}

const size_t falcon_max_bl_small[FALCON_MAX_BL_SMALL_SIZE] = { 1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209 };

const size_t falcon_max_bl_large[FALCON_MAX_BL_LARGE_SIZE] = { 2, 2, 5, 7, 12, 21, 40, 78, 157, 308 };

static uint32_t falcon_poly_small_sqnorm(const int8_t* f, uint32_t logn)
{
	/*
	* Compute squared norm of a short vector. Returned value is saturated to
	* 2^32-1 if it is not lower than 2^31.
	*/

	size_t n;
	size_t u;
	uint32_t s;
	uint32_t ng;

	n = falcon_mkn(logn);
	s = 0;
	ng = 0;

	for (u = 0; u < n; ++u)
	{
		int32_t z;

		z = f[u];
		s += (uint32_t)(z * z);
		ng |= s;
	}

	return (s | (uint32_t)-(int32_t)(ng >> 31));
}

static falcon_fpr* falcon_align_fpr(void* base, const void* data)
{
	/*
	* Align (upwards) the provided 'data' pointer with regards to 'base'
	* so that the offset is a multiple of the size of 'falcon_fpr'.
	*/

	uint8_t* cb;
	const uint8_t* cd;
	size_t k;
	size_t km;

	cb = base;
	cd = data;
	k = (size_t)(cd - cb);
	km = k % sizeof(falcon_fpr);

	if (km != 0)
	{
		k += (sizeof(falcon_fpr)) - km;
	}

	return (falcon_fpr *)(cb + k);
}

static uint32_t* falcon_align_u32(void* base, const void* data)
{
	/*
	* Align (upwards) the provided 'data' pointer with regards to 'base'
	* so that the offset is a multiple of the size of 'uint32_t'.
	*/

	uint8_t* cb;
	const uint8_t* cd;
	size_t k;
	size_t km;

	cb = base;
	cd = data;
	k = (size_t)(cd - cb);
	km = k % sizeof(uint32_t);

	if (km != 0)
	{
		k += (sizeof(uint32_t)) - km;
	}

	return (uint32_t *)(cb + k);
}

static void falcon_poly_small_to_fp(falcon_fpr* x, const int8_t* f, uint32_t logn)
{
	/*
	* Convert a small vector to floating point.
	*/
	size_t n;
	size_t u;

	n = falcon_mkn(logn);

	for (u = 0; u < n; ++u)
	{
		x[u] = falcon_fpr_of(f[u]);
	}
}

static void falcon_make_fg_step(uint32_t *data, uint32_t logn, uint32_t depth, int32_t in_ntt, int32_t out_ntt)
{
	/*
	* Input: f,g of degree N = 2^logn; 'depth' is used only to get their
	* individual length.
	*
	* Output: f',g' of degree N/2, with the length for 'depth+1'.
	*
	* Values are in RNS; input and/or output may also be in NTT.
	*/

	size_t n;
	size_t hn;
	size_t u;
	size_t slen;
	size_t tlen;
	uint32_t* fd;
	uint32_t* gd;
	uint32_t* fs;
	uint32_t* gs;
	uint32_t* gm;
	uint32_t* igm;
	uint32_t* t1;
	const falcon_small_prime* primes;

	n = (size_t)1 << logn;
	hn = n >> 1;
	slen = falcon_max_bl_small[depth];
	tlen = falcon_max_bl_small[depth + 1];
	primes = falcon_small_primes;

	/*
	 * Prepare room for the result.
	 */
	fd = data;
	gd = fd + hn * tlen;
	fs = gd + hn * tlen;
	gs = fs + n * slen;
	gm = gs + n * slen;
	igm = gm + n;
	t1 = igm + n;
	qsc_memutils_move(fs, data, 2 * n * slen * sizeof(*data));

	/*
	 * First slen words: we use the input values directly, and apply
	 * inverse NTT as we go.
	 */
	for (u = 0; u < slen; ++u)
	{
		size_t v;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t* x;

		p = primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);
		falcon_modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

		for (v = 0, x = fs + u; v < n; v++, x += slen)
		{
			t1[v] = *x;
		}

		if (in_ntt == 0)
		{
			falcon_modp_NTT2_ext(t1, 1, gm, logn, p, p0i);
		}

		for (v = 0, x = fd + u; v < hn; v++, x += tlen)
		{
			uint32_t w0;
			uint32_t w1;

			w0 = t1[v << 1];
			w1 = t1[(v << 1) + 1];
			*x = falcon_modp_montymul(falcon_modp_montymul(w0, w1, p, p0i), R2, p, p0i);
		}

		if (in_ntt != 0)
		{
			falcon_modp_iNTT2_ext(fs + u, slen, igm, logn, p, p0i);
		}

		for (v = 0, x = gs + u; v < n; v++, x += slen)
		{
			t1[v] = *x;
		}

		if (in_ntt == 0)
		{
			falcon_modp_NTT2_ext(t1, 1, gm, logn, p, p0i);
		}

		for (v = 0, x = gd + u; v < hn; v++, x += tlen)
		{
			uint32_t w0;
			uint32_t w1;

			w0 = t1[v << 1];
			w1 = t1[(v << 1) + 1];
			*x = falcon_modp_montymul(falcon_modp_montymul(w0, w1, p, p0i), R2, p, p0i);
		}

		if (in_ntt != 0)
		{
			falcon_modp_iNTT2_ext(gs + u, slen, igm, logn, p, p0i);
		}

		if (out_ntt == 0)
		{
			falcon_modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
			falcon_modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
		}
	}

	/*
	 * Since the fs and gs words have been de-NTTized, we can use the
	 * CRT to rebuild the values.
	 */
	falcon_zint_rebuild_CRT(fs, slen, slen, n, primes, 1, gm);
	falcon_zint_rebuild_CRT(gs, slen, slen, n, primes, 1, gm);

	/*
	 * Remaining words: use modular reductions to extract the values.
	 */
	for (u = slen; u < tlen; ++u)
	{
		size_t v;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t Rx;
		uint32_t* x;

		p = primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);
		Rx = falcon_modp_Rx((uint32_t)slen, p, p0i, R2);
		falcon_modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

		for (v = 0, x = fs; v < n; v++, x += slen)
		{
			t1[v] = falcon_zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
		}

		falcon_modp_NTT2_ext(t1, 1, gm, logn, p, p0i);

		for (v = 0, x = fd + u; v < hn; v++, x += tlen)
		{
			uint32_t w0;
			uint32_t w1;

			w0 = t1[v << 1];
			w1 = t1[(v << 1) + 1];
			*x = falcon_modp_montymul(falcon_modp_montymul(w0, w1, p, p0i), R2, p, p0i);
		}

		for (v = 0, x = gs; v < n; v++, x += slen)
		{
			t1[v] = falcon_zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
		}

		falcon_modp_NTT2_ext(t1, 1, gm, logn, p, p0i);

		for (v = 0, x = gd + u; v < hn; v++, x += tlen)
		{
			uint32_t w0;
			uint32_t w1;

			w0 = t1[v << 1];
			w1 = t1[(v << 1) + 1];
			*x = falcon_modp_montymul(falcon_modp_montymul(w0, w1, p, p0i), R2, p, p0i);
		}

		if (out_ntt == 0)
		{
			falcon_modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
			falcon_modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
		}
	}
}

static void falcon_make_fg(uint32_t* data, const int8_t* f, const int8_t* g, uint32_t logn, uint32_t depth, int32_t out_ntt)
{
	/*
	* Compute f and g at a specific depth, in RNS notation.
	*
	* Returned values are stored in the data[] array, at slen words per integer.
	*
	* Conditions:
	*   0 <= depth <= logn
	*
	* Space use in data[]: enough room for any two successive values (f', g',
	* f and g).
	*/

	size_t n;
	size_t u;
	uint32_t* ft;
	uint32_t* gt;
	uint32_t p0;
	uint32_t d;
	const falcon_small_prime* primes;

	n = falcon_mkn(logn);
	ft = data;
	gt = ft + n;
	primes = falcon_small_primes;
	p0 = primes[0].p;

	for (u = 0; u < n; ++u)
	{
		ft[u] = falcon_modp_set(f[u], p0);
		gt[u] = falcon_modp_set(g[u], p0);
	}

	if (depth == 0 && out_ntt)
	{
		uint32_t* gm;
		uint32_t* igm;
		uint32_t p;
		uint32_t p0i;

		p = primes[0].p;
		p0i = falcon_modp_ninv31(p);
		gm = gt + n;
		igm = gm + falcon_mkn(logn);
		falcon_modp_mkgm2(gm, igm, logn, primes[0].g, p, p0i);
		falcon_modp_NTT2_ext(ft, 1, gm, logn, p, p0i);
		falcon_modp_NTT2_ext(gt, 1, gm, logn, p, p0i);

		return;
	}

	for (d = 0; d < depth; ++d)
	{
		falcon_make_fg_step(data, logn - d, d, d != 0, (d + 1) < depth || out_ntt);
	}
}

static int32_t falcon_solve_NTRU_deepest(uint32_t logn_top, const int8_t* f, const int8_t* g, uint32_t* tmp)
{
	/*
	* Solving the NTRU equation, deepest level: compute the resultants of
	* f and g with X^N+1, and use binary GCD. The F and G values are
	* returned in tmp[].
	*
	* Returned value: 1 on success, 0 on error.
	*/

	size_t len;
	uint32_t* Fp;
	uint32_t* Gp;
	uint32_t* fp;
	uint32_t* gp;
	uint32_t* t1;
	uint32_t q;
	const falcon_small_prime* primes;

	len = falcon_max_bl_small[logn_top];
	primes = falcon_small_primes;

	Fp = tmp;
	Gp = Fp + len;
	fp = Gp + len;
	gp = fp + len;
	t1 = gp + len;

	falcon_make_fg(fp, f, g, logn_top, logn_top, 0);

	/*
	 * We use the CRT to rebuild the resultants as big integers.
	 * There are two such big integers. The resultants are always
	 * nonnegative.
	 */
	falcon_zint_rebuild_CRT(fp, len, len, 2, primes, 0, t1);

	/*
	 * Apply the binary GCD. The falcon_zint_bezout() function works only
	 * if both inputs are odd.
	 *
	 * We can test on the result and return 0 because that would
	 * imply failure of the NTRU solving equation, and the (f,g)
	 * values will be abandoned in that case.
	 */
	if (falcon_zint_bezout(Gp, Fp, fp, gp, len, t1) == 0)
	{
		return 0;
	}

	/*
	 * Multiply the two values by the target value q. Values must
	 * fit in the destination arrays.
	 * We can again test on the returned words: a non-zero output
	 * of falcon_zint_mul_small() means that we exceeded our array
	 * capacity, and that implies failure and rejection of (f,g).
	 */
	q = 12289;

	if (falcon_zint_mul_small(Fp, len, q) != 0 || falcon_zint_mul_small(Gp, len, q) != 0)
	{
		return 0;
	}

	return 1;
}

static int32_t falcon_solve_NTRU_intermediate(uint32_t logn_top, const int8_t* f, const int8_t* g, uint32_t depth, uint32_t* tmp)
{
	/*
	* Solving the NTRU equation, intermediate level. Upon entry, the F and G
	* from the previous level should be in the tmp[] array.
	* This function MAY be invoked for the top-level (in which case depth = 0).
	*
	* Returned value: 1 on success, 0 on error.
	*
	* In this function, 'logn' is the log2 of the degree for
	* this step. If N = 2^logn, then:
	*  - the F and G values already in fk->tmp (from the deeper levels) have degree N/2
	*  - this function should return F and G of degree N.
	*/

	falcon_fpr* rt1;
	falcon_fpr* rt2;
	falcon_fpr* rt3;
	falcon_fpr* rt4;
	falcon_fpr* rt5;
	size_t n;
	size_t hn;
	size_t slen;
	size_t dlen;
	size_t llen;
	size_t rlen;
	size_t FGlen;
	size_t u;
	uint32_t* Fd;
	uint32_t* Gd;
	uint32_t* Ft;
	uint32_t* Gt;
	uint32_t* ft;
	uint32_t* gt;
	uint32_t* t1;
	uint32_t* x;
	uint32_t* y;
	uint32_t logn;
	int32_t* k;
	int32_t scale_fg;
	int32_t minbl_fg;
	int32_t maxbl_fg;
	int32_t maxbl_FG;
	int32_t scale_k;
	const falcon_small_prime* primes;

	logn = logn_top - depth;
	n = (size_t)1 << logn;
	hn = n >> 1;

	/*
	 * slen = size for our input f and g; also size of the reduced
	 *        F and G we return (degree N)
	 *
	 * dlen = size of the F and G obtained from the deeper level
	 *        (degree N/2 or N/3)
	 *
	 * llen = size for intermediary F and G before reduction (degree N)
	 *
	 * We build our non-reduced F and G as two independent halves each,
	 * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
	 */
	slen = falcon_max_bl_small[depth];
	dlen = falcon_max_bl_small[depth + 1];
	llen = falcon_max_bl_large[depth];
	primes = falcon_small_primes;

	/*
	 * Fd and Gd are the F and G from the deeper level.
	 */
	Fd = tmp;
	Gd = Fd + dlen * hn;

	/*
	 * Compute the input f and g for this level. Note that we get f
	 * and g in RNS + NTT representation.
	 */
	ft = Gd + dlen * hn;
	falcon_make_fg(ft, f, g, logn_top, depth, 1);

	/*
	 * Move the newly computed f and g to make room for our candidate
	 * F and G (unreduced).
	 */
	Ft = tmp;
	Gt = Ft + n * llen;
	t1 = Gt + n * llen;
	qsc_memutils_move(t1, ft, 2 * n * slen * sizeof(*ft));
	ft = t1;
	gt = ft + slen * n;
	t1 = gt + slen * n;

	/*
	 * Move Fd and Gd _after_ f and g.
	 */
	qsc_memutils_move(t1, Fd, 2 * hn * dlen * sizeof(*Fd));
	Fd = t1;
	Gd = Fd + hn * dlen;

	/*
	 * We reduce Fd and Gd modulo all the small primes we will need,
	 * and store the values in Ft and Gt (only n/2 values in each).
	 */
	for (u = 0; u < llen; ++u)
	{
		size_t v;
		const uint32_t* xs;
		const uint32_t* ys;
		uint32_t* xd;
		uint32_t* yd;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t Rx;

		p = primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);
		Rx = falcon_modp_Rx((uint32_t)dlen, p, p0i, R2);

		for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u; v < hn; v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
		{
			*xd = falcon_zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
			*yd = falcon_zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
		}
	}

	/*
	 * We do not need Fd and Gd after that point.
	 */

	 /*
	  * Compute our F and G modulo sufficiently many small primes.
	  */
	for (u = 0; u < llen; ++u)
	{
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t* gm;
		uint32_t* igm;
		uint32_t* fx;
		uint32_t* gx;
		uint32_t* Fp;
		uint32_t* Gp;
		size_t v;

		/*
		 * All computations are done modulo p.
		 */
		p = primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);

		/*
		 * If we processed slen words, then f and g have been
		 * de-NTTized, and are in RNS; we can rebuild them.
		 */
		if (u == slen)
		{
			falcon_zint_rebuild_CRT(ft, slen, slen, n, primes, 1, t1);
			falcon_zint_rebuild_CRT(gt, slen, slen, n, primes, 1, t1);
		}

		gm = t1;
		igm = gm + n;
		fx = igm + n;
		gx = fx + n;

		falcon_modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

		if (u < slen)
		{
			for (v = 0, x = ft + u, y = gt + u; v < n; v++, x += slen, y += slen)
			{
				fx[v] = *x;
				gx[v] = *y;
			}

			falcon_modp_iNTT2_ext(ft + u, slen, igm, logn, p, p0i);
			falcon_modp_iNTT2_ext(gt + u, slen, igm, logn, p, p0i);
		}
		else
		{
			uint32_t Rx;

			Rx = falcon_modp_Rx((uint32_t)slen, p, p0i, R2);

			for (v = 0, x = ft, y = gt; v < n; v++, x += slen, y += slen)
			{
				fx[v] = falcon_zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
				gx[v] = falcon_zint_mod_small_signed(y, slen, p, p0i, R2, Rx);
			}

			falcon_modp_NTT2_ext(fx, 1, gm, logn, p, p0i);
			falcon_modp_NTT2_ext(gx, 1, gm, logn, p, p0i);
		}

		/*
		 * Get F' and G' modulo p and in NTT representation
		 * (they have degree n/2). These values were computed in
		 * a previous step, and stored in Ft and Gt.
		 */
		Fp = gx + n;
		Gp = Fp + hn;

		for (v = 0, x = Ft + u, y = Gt + u; v < hn; v++, x += llen, y += llen)
		{
			Fp[v] = *x;
			Gp[v] = *y;
		}

		falcon_modp_NTT2_ext(Fp, 1, gm, logn - 1, p, p0i);
		falcon_modp_NTT2_ext(Gp, 1, gm, logn - 1, p, p0i);

		/*
		 * Compute our F and G modulo p.
		 *
		 * General case:
		 *
		 *   we divide degree by d = 2 or 3
		 *   f'(x^d) = N(f)(x^d) = f * adj(f)
		 *   g'(x^d) = N(g)(x^d) = g * adj(g)
		 *   f'*G' - g'*F' = q
		 *   F = F'(x^d) * adj(g)
		 *   G = G'(x^d) * adj(f)
		 *
		 * We compute things in the NTT. We group roots of phi
		 * such that all roots x in a group share the same x^d.
		 * If the roots in a group are x_1, x_2... x_d, then:
		 *
		 *   N(f)(x_1^d) = f(x_1)*f(x_2)*...*f(x_d)
		 *
		 * Thus, we have:
		 *
		 *   G(x_1) = f(x_2)*f(x_3)*...*f(x_d)*G'(x_1^d)
		 *   G(x_2) = f(x_1)*f(x_3)*...*f(x_d)*G'(x_1^d)
		 *   ...
		 *   G(x_d) = f(x_1)*f(x_2)*...*f(x_{d-1})*G'(x_1^d)
		 *
		 * In all cases, we can thus compute F and G in NTT
		 * representation by a few simple multiplications.
		 * Moreover, in our chosen NTT representation, roots
		 * from the same group are consecutive in RAM.
		 */
		for (v = 0, x = Ft + u, y = Gt + u; v < hn; v++, x += (llen << 1), y += (llen << 1))
		{
			uint32_t ftA;
			uint32_t ftB;
			uint32_t gtA;
			uint32_t gtB;
			uint32_t mFp;
			uint32_t mGp;

			ftA = fx[v << 1];
			ftB = fx[(v << 1) + 1];
			gtA = gx[v << 1];
			gtB = gx[(v << 1) + 1];
			mFp = falcon_modp_montymul(Fp[v], R2, p, p0i);
			mGp = falcon_modp_montymul(Gp[v], R2, p, p0i);
			x[0] = falcon_modp_montymul(gtB, mFp, p, p0i);
			x[llen] = falcon_modp_montymul(gtA, mFp, p, p0i);
			y[0] = falcon_modp_montymul(ftB, mGp, p, p0i);
			y[llen] = falcon_modp_montymul(ftA, mGp, p, p0i);
		}

		falcon_modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
		falcon_modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);
	}

	/*
	 * Rebuild F and G with the CRT.
	 */
	falcon_zint_rebuild_CRT(Ft, llen, llen, n, primes, 1, t1);
	falcon_zint_rebuild_CRT(Gt, llen, llen, n, primes, 1, t1);

	/*
	 * At that point, Ft, Gt, ft and gt are consecutive in RAM (in that
	 * order).
	 */

	 /*
	  * Apply Babai reduction to bring back F and G to size slen.
	  *
	  * We use the FFT to compute successive approximations of the
	  * reduction coefficient. We first isolate the top bits of
	  * the coefficients of f and g, and convert them to floating
	  * point; with the FFT, we compute adj(f), adj(g), and
	  * 1/(f*adj(f)+g*adj(g)).
	  *
	  * Then, we repeatedly apply the following:
	  *
	  *   - Get the top bits of the coefficients of F and G into
	  *     floating point, and use the FFT to compute:
	  *        (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g))
	  *
	  *   - Convert back that value into normal representation, and
	  *     round it to the nearest integers, yielding a polynomial k.
	  *     Proper scaling is applied to f, g, F and G so that the
	  *     coefficients fit on 32 bits (signed).
	  *
	  *   - Subtract k*f from F and k*g from G.
	  *
	  * Under normal conditions, this process reduces the size of F
	  * and G by some bits at each iteration. For constant-time
	  * operation, we do not want to measure the actual length of
	  * F and G; instead, we do the following:
	  *
	  *   - f and g are converted to floating-point, with some scaling
	  *     if necessary to keep values in the representable range.
	  *
	  *   - For each iteration, we _assume_ a maximum size for F and G,
	  *     and use the values at that size. If we overreach, then
	  *     we get zeros, which is harmless: the resulting coefficients
	  *     of k will be 0 and the value won't be reduced.
	  *
	  *   - We conservatively assume that F and G will be reduced by
	  *     at least 25 bits at each iteration.
	  *
	  * Even when reaching the bottom of the reduction, reduction
	  * coefficient will remain low. If it goes out-of-range, then
	  * something wrong occurred and the whole NTRU solving fails.
	  */

	  /*
	   * Memory layout:
	   *  - We need to compute and keep adj(f), adj(g), and
	   *    1/(f*adj(f)+g*adj(g)) (sizes N, N and N/2 fp numbers,
	   *    respectively).
	   *  - At each iteration we need two extra fp buffer (N fp values),
	   *    and produce a k (N 32-bit words). k will be shared with one
	   *    of the fp buffers.
	   *  - To compute k*f and k*g efficiently (with the NTT), we need
	   *    some extra room; we reuse the space of the temporary buffers.
	   *
	   * Arrays of 'falcon_fpr' are obtained from the temporary array itself.
	   * We ensure that the base is at a properly aligned offset (the
	   * source array tmp[] is supposed to be already aligned).
	   */

	rt3 = falcon_align_fpr(tmp, t1);
	rt4 = rt3 + n;
	rt5 = rt4 + n;
	rt1 = rt5 + (n >> 1);
	k = (int32_t*)falcon_align_u32(tmp, rt1);
	rt2 = falcon_align_fpr(tmp, k + n);

	if (rt2 < (rt1 + n))
	{
		rt2 = rt1 + n;
	}

	t1 = (uint32_t*)k + n;

	/*
	 * Get f and g into rt3 and rt4 as floating-point approximations.
	 *
	 * We need to "scale down" the floating-point representation of
	 * coefficients when they are too big. We want to keep the value
	 * below 2^310 or so. Thus, when values are larger than 10 words,
	 * we consider only the top 10 words. Array lengths have been
	 * computed so that average maximum length will fall in the
	 * middle or the upper half of these top 10 words.
	 */
	rlen = (slen > 10) ? 10 : slen;
	falcon_poly_big_to_fp(rt3, ft + slen - rlen, rlen, slen, logn);
	falcon_poly_big_to_fp(rt4, gt + slen - rlen, rlen, slen, logn);

	/*
	 * Values in rt3 and rt4 are downscaled by 2^(scale_fg).
	 */
	scale_fg = 31 * (int32_t)(slen - rlen);

	/*
	 * Estimated boundaries for the maximum size (in bits) of the
	 * coefficients of (f,g). We use the measured average, and
	 * allow for a deviation of at most six times the standard
	 * deviation.
	 */
	minbl_fg = falcon_bit_length[depth].avg - 6 * falcon_bit_length[depth].std;
	maxbl_fg = falcon_bit_length[depth].avg + 6 * falcon_bit_length[depth].std;

	/*
	 * Compute 1/(f*adj(f)+g*adj(g)) in rt5. We also keep adj(f)
	 * and adj(g) in rt3 and rt4, respectively.
	 */
	falcon_FFT(rt3, logn);
	falcon_FFT(rt4, logn);
	falcon_poly_invnorm2_fft(rt5, rt3, rt4, logn);
	falcon_poly_adj_fft(rt3, logn);
	falcon_poly_adj_fft(rt4, logn);

	/*
	 * Reduce F and G repeatedly.
	 *
	 * The expected maximum bit length of coefficients of F and G
	 * is kept in maxbl_FG, with the corresponding word length in
	 * FGlen.
	 */
	FGlen = llen;
	maxbl_FG = 31 * (int32_t)llen;

	/*
	 * Each reduction operation computes the reduction polynomial
	 * "k". We need that polynomial to have coefficients that fit
	 * on 32-bit signed integers, with some scaling; thus, we use
	 * a descending sequence of scaling values, down to zero.
	 *
	 * The size of the coefficients of k is (roughly) the difference
	 * between the size of the coefficients of (F,G) and the size
	 * of the coefficients of (f,g). Thus, the maximum size of the
	 * coefficients of k is, at the start, maxbl_FG - minbl_fg
	 * this is our starting scale value for k.
	 *
	 * We need to estimate the size of (F,G) during the execution of
	 * the algorithm; we are allowed some overestimation but not too
	 * much (falcon_poly_big_to_fp() uses a 310-bit window). Generally
	 * speaking, after applying a reduction with k scaled to
	 * scale_k, the size of (F,G) will be size(f,g) + scale_k + dd,
	 * where 'dd' is a few bits to account for the fact that the
	 * reduction is never perfect (intuitively, dd is on the order
	 * of sqrt(N), so at most 5 bits; we here allow for 10 extra
	 * bits).
	 *
	 * The size of (f,g) is not known exactly, but maxbl_fg is an
	 * upper bound.
	 */
	scale_k = maxbl_FG - minbl_fg;

	while (true)
	{
		falcon_fpr pdc;
		falcon_fpr pt;
		uint32_t scl;
		uint32_t sch;
		int32_t scale_FG;
		int32_t dc;
		int32_t new_maxbl_FG;

		/*
		 * Convert current F and G into floating-point. We apply
		 * scaling if the current length is more than 10 words.
		 */
		rlen = (FGlen > 10) ? 10 : FGlen;
		scale_FG = 31 * (int32_t)(FGlen - rlen);
		falcon_poly_big_to_fp(rt1, Ft + FGlen - rlen, rlen, llen, logn);
		falcon_poly_big_to_fp(rt2, Gt + FGlen - rlen, rlen, llen, logn);

		/*
		 * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) in rt2.
		 */
		falcon_FFT(rt1, logn);
		falcon_FFT(rt2, logn);
		falcon_poly_mul_fft(rt1, rt3, logn);
		falcon_poly_mul_fft(rt2, rt4, logn);
		falcon_poly_add(rt2, rt1, logn);
		falcon_poly_mul_autoadj_fft(rt2, rt5, logn);
		falcon_iFFT(rt2, logn);

		/*
		 * (f,g) are scaled by 'scale_fg', meaning that the
		 * numbers in rt3/rt4 should be multiplied by 2^(scale_fg)
		 * to have their true mathematical value.
		 *
		 * (F,G) are similarly scaled by 'scale_FG'. Therefore,
		 * the value we computed in rt2 is scaled by
		 * 'scale_FG-scale_fg'.
		 *
		 * We want that value to be scaled by 'scale_k', hence we
		 * apply a corrective scaling. After scaling, the values
		 * should fit in -2^31-1..+2^31-1.
		 */
		dc = scale_k - scale_FG + scale_fg;

		/*
		 * We will need to multiply values by 2^(-dc). The value
		 * 'dc' is not secret, so we can compute 2^(-dc) with a
		 * non-constant-time process.
		 * (We could use ldexp(), but we prefer to avoid any
		 * dependency on libm. When using FP emulation, we could
		 * use our fpr_ldexp(), which is constant-time.)
		 */
		if (dc < 0)
		{
			dc = -dc;
			pt = falcon_fpr_two;
		}
		else
		{
			pt = falcon_fpr_onehalf;
		}

		pdc = falcon_fpr_one;

		while (dc != 0)
		{
			if ((dc & 1) != 0)
			{
				pdc = falcon_fpr_mul(pdc, pt);
			}

			dc >>= 1;
			pt = falcon_fpr_sqr(pt);
		}

		for (u = 0; u < n; ++u)
		{
			falcon_fpr xv;

			xv = falcon_fpr_mul(rt2[u], pdc);

			/*
			 * Sometimes the values can be out-of-bounds if
			 * the algorithm fails; we must not call
			 * falcon_fpr_rint() (and cast to int32_t) if the value
			 * is not in-bounds. Note that the test does not
			 * break constant-time discipline, since any
			 * failure here implies that we discard the current
			 * secret key (f,g).
			 */
			if (falcon_fpr_lt(falcon_fpr_mtwo31m1, xv) == 0 || falcon_fpr_lt(xv, falcon_fpr_ptwo31m1) == 0)
			{
				return 0;
			}

			k[u] = (int32_t)falcon_fpr_rint(xv);
		}

		/*
		 * Values in k[] are integers. They really are scaled
		 * down by maxbl_FG - minbl_fg bits.
		 *
		 * If we are at low depth, then we use the NTT to
		 * compute k*f and k*g.
		 */
		sch = (uint32_t)(scale_k / 31);
		scl = (uint32_t)(scale_k % 31);

		if (depth <= FALCON_DEPTH_INT_FG)
		{
			falcon_poly_sub_scaled_ntt(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn, t1);
			falcon_poly_sub_scaled_ntt(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn, t1);
		}
		else
		{
			falcon_poly_sub_scaled(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn);
			falcon_poly_sub_scaled(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn);
		}

		/*
		 * We compute the new maximum size of (F,G), assuming that
		 * (f,g) has _maximal_ length (i.e. that reduction is
		 * "late" instead of "early". We also adjust FGlen
		 * accordingly.
		 */
		new_maxbl_FG = scale_k + maxbl_fg + 10;

		if (new_maxbl_FG < maxbl_FG)
		{
			maxbl_FG = new_maxbl_FG;

			if ((int32_t)FGlen * 31 >= maxbl_FG + 31)
			{
				FGlen--;
			}
		}

		/*
		 * We suppose that scaling down achieves a reduction by
		 * at least 25 bits per iteration. We stop when we have
		 * done the loop with an unscaled k.
		 */
		if (scale_k <= 0)
		{
			break;
		}

		scale_k -= 25;

		if (scale_k < 0)
		{
			scale_k = 0;
		}
	}

	/*
	 * If (F,G) length was lowered below 'slen', then we must take
	 * care to re-extend the sign.
	 */
	if (FGlen < slen)
	{
		for (u = 0; u < n; u++, Ft += llen, Gt += llen)
		{
			size_t v;
			uint32_t sw;

			sw = (uint32_t)-(int32_t)(Ft[FGlen - 1] >> 30) >> 1;

			for (v = FGlen; v < slen; v++)
			{
				Ft[v] = sw;
			}

			sw = (uint32_t)-(int32_t)(Gt[FGlen - 1] >> 30) >> 1;

			for (v = FGlen; v < slen; v++)
			{
				Gt[v] = sw;
			}
		}
	}

	/*
	 * Compress encoding of all values to 'slen' words (this is the
	 * expected output format).
	 */
	for (u = 0, x = tmp, y = tmp; u < (n << 1); u++, x += slen, y += llen)
	{
		qsc_memutils_move(x, y, slen * sizeof(*y));
	}

	return 1;
}

static int32_t falcon_solve_NTRU_binary_depth1(uint32_t logn_top, const int8_t* f, const int8_t* g, uint32_t* tmp)
{
	/*
	* Solving the NTRU equation, binary case, depth = 1. Upon entry, the
	* F and G from the previous level should be in the tmp[] array.
	*
	* The first half of this function is a copy of the corresponding
	* part in falcon_solve_NTRU_intermediate(), for the reconstruction of
	* the unreduced F and G. The second half (Babai reduction) is
	* done differently, because the unreduced F and G fit in 53 bits
	* of precision, allowing a much simpler process with lower RAM
	* usage.
	*/

	falcon_fpr* rt1;
	falcon_fpr* rt2;
	falcon_fpr* rt3;
	falcon_fpr* rt4;
	falcon_fpr* rt5;
	falcon_fpr* rt6;
	size_t n_top;
	size_t n;
	size_t hn;
	size_t slen;
	size_t dlen;
	size_t llen;
	size_t u;
	uint32_t* Fd;
	uint32_t* Gd;
	uint32_t* Ft;
	uint32_t* Gt;
	uint32_t* ft;
	uint32_t* gt;
	uint32_t* t1;
	uint32_t* x;
	uint32_t* y;
	uint32_t depth;
	uint32_t logn;

	depth = 1;
	n_top = (size_t)1 << logn_top;
	logn = logn_top - depth;
	n = (size_t)1 << logn;
	hn = n >> 1;

	/*
	 * Equations are:
	 *
	 *   f' = f0^2 - X^2*f1^2
	 *   g' = g0^2 - X^2*g1^2
	 *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
	 *   F = F'*(g0 - X*g1)
	 *   G = G'*(f0 - X*f1)
	 *
	 * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
	 * degree N/2 (their odd-indexed coefficients are all zero).
	 */

	 /*
	  * slen = size for our input f and g; also size of the reduced
	  *        F and G we return (degree N)
	  *
	  * dlen = size of the F and G obtained from the deeper level
	  *        (degree N/2)
	  *
	  * llen = size for intermediary F and G before reduction (degree N)
	  *
	  * We build our non-reduced F and G as two independent halves each,
	  * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
	  */
	slen = falcon_max_bl_small[depth];
	dlen = falcon_max_bl_small[depth + 1];
	llen = falcon_max_bl_large[depth];

	/*
	 * Fd and Gd are the F and G from the deeper level. Ft and Gt
	 * are the destination arrays for the unreduced F and G.
	 */
	Fd = tmp;
	Gd = Fd + dlen * hn;
	Ft = Gd + dlen * hn;
	Gt = Ft + llen * n;

	/*
	 * We reduce Fd and Gd modulo all the small primes we will need,
	 * and store the values in Ft and Gt.
	 */
	for (u = 0; u < llen; ++u)
	{
		size_t v;
		const uint32_t* xs;
		const uint32_t* ys;
		uint32_t* xd;
		uint32_t* yd;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;
		uint32_t Rx;

		p = falcon_small_primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);
		Rx = falcon_modp_Rx((uint32_t)dlen, p, p0i, R2);

		for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u; v < hn; v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
		{
			*xd = falcon_zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
			*yd = falcon_zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
		}
	}

	/*
	 * Now Fd and Gd are not needed anymore; we can squeeze them out.
	 */
	qsc_memutils_move(tmp, Ft, llen * n * sizeof(uint32_t));
	Ft = tmp;
	qsc_memutils_move(Ft + llen * n, Gt, llen * n * sizeof(uint32_t));
	Gt = Ft + llen * n;
	ft = Gt + llen * n;
	gt = ft + slen * n;

	t1 = gt + slen * n;

	/*
	 * Compute our F and G modulo sufficiently many small primes.
	 */
	for (u = 0; u < llen; ++u)
	{
		size_t v;
		uint32_t* gm;
		uint32_t* igm;
		uint32_t* fx;
		uint32_t* gx;
		uint32_t* Fp;
		uint32_t* Gp;
		uint32_t e;
		uint32_t p;
		uint32_t p0i;
		uint32_t R2;

		/*
		 * All computations are done modulo p.
		 */
		p = falcon_small_primes[u].p;
		p0i = falcon_modp_ninv31(p);
		R2 = falcon_modp_R2(p, p0i);

		/*
		 * We recompute things from the source f and g, of full
		 * degree. However, we will need only the n first elements
		 * of the inverse NTT table (igm); the call to modp_mkgm()
		 * below will fill n_top elements in igm[] (thus overflowing
		 * into fx[]) but later code will overwrite these extra
		 * elements.
		 */
		gm = t1;
		igm = gm + n_top;
		fx = igm + n;
		gx = fx + n_top;
		falcon_modp_mkgm2(gm, igm, logn_top, falcon_small_primes[u].g, p, p0i);

		/*
		 * Set ft and gt to f and g modulo p, respectively.
		 */
		for (v = 0; v < n_top; ++v)
		{
			fx[v] = falcon_modp_set(f[v], p);
			gx[v] = falcon_modp_set(g[v], p);
		}

		/*
		 * Convert to NTT and compute our f and g.
		 */
		falcon_modp_NTT2_ext(fx, 1, gm, logn_top, p, p0i);
		falcon_modp_NTT2_ext(gx, 1, gm, logn_top, p, p0i);

		for (e = logn_top; e > logn; e--)
		{
			falcon_modp_poly_rec_res(fx, e, p, p0i, R2);
			falcon_modp_poly_rec_res(gx, e, p, p0i, R2);
		}

		/*
		 * From that point onward, we only need tables for
		 * degree n, so we can save some space.
		 */
		if (depth > 0)
		{
			qsc_memutils_move(gm + n, igm, n * sizeof(*igm));
			igm = gm + n;
			qsc_memutils_move(igm + n, fx, n * sizeof(*ft));
			fx = igm + n;
			qsc_memutils_move(fx + n, gx, n * sizeof(*gt));
			gx = fx + n;
		}

		/*
		 * Get F' and G' modulo p and in NTT representation
		 * (they have degree n/2). These values were computed
		 * in a previous step, and stored in Ft and Gt.
		 */
		Fp = gx + n;
		Gp = Fp + hn;

		for (v = 0, x = Ft + u, y = Gt + u; v < hn; v++, x += llen, y += llen)
		{
			Fp[v] = *x;
			Gp[v] = *y;
		}

		falcon_modp_NTT2_ext(Fp, 1, gm, logn - 1, p, p0i);
		falcon_modp_NTT2_ext(Gp, 1, gm, logn - 1, p, p0i);

		/*
		 * Compute our F and G modulo p.
		 *
		 * Equations are:
		 *
		 *   f'(x^2) = N(f)(x^2) = f * adj(f)
		 *   g'(x^2) = N(g)(x^2) = g * adj(g)
		 *
		 *   f'*G' - g'*F' = q
		 *
		 *   F = F'(x^2) * adj(g)
		 *   G = G'(x^2) * adj(f)
		 *
		 * The NTT representation of f is f(w) for all w which
		 * are roots of phi. In the binary case, as well as in
		 * the ternary case for all depth except the deepest,
		 * these roots can be grouped in pairs (w,-w), and we
		 * then have:
		 *
		 *   f(w) = adj(f)(-w)
		 *   f(-w) = adj(f)(w)
		 *
		 * and w^2 is then a root for phi at the half-degree.
		 *
		 * At the deepest level in the ternary case, this still
		 * holds, in the following sense: the roots of x^2-x+1
		 * are (w,-w^2) (for w^3 = -1, and w != -1), and we
		 * have:
		 *
		 *   f(w) = adj(f)(-w^2)
		 *   f(-w^2) = adj(f)(w)
		 *
		 * In all case, we can thus compute F and G in NTT
		 * representation by a few simple multiplications.
		 * Moreover, the two roots for each pair are consecutive
		 * in our bit-reversal encoding.
		 */
		for (v = 0, x = Ft + u, y = Gt + u; v < hn; v++, x += (llen << 1), y += (llen << 1))
		{
			uint32_t ftA;
			uint32_t ftB;
			uint32_t gtA;
			uint32_t gtB;
			uint32_t mFp;
			uint32_t mGp;

			ftA = fx[v << 1];
			ftB = fx[(v << 1) + 1];
			gtA = gx[v << 1];
			gtB = gx[(v << 1) + 1];
			mFp = falcon_modp_montymul(Fp[v], R2, p, p0i);
			mGp = falcon_modp_montymul(Gp[v], R2, p, p0i);
			x[0] = falcon_modp_montymul(gtB, mFp, p, p0i);
			x[llen] = falcon_modp_montymul(gtA, mFp, p, p0i);
			y[0] = falcon_modp_montymul(ftB, mGp, p, p0i);
			y[llen] = falcon_modp_montymul(ftA, mGp, p, p0i);
		}

		falcon_modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
		falcon_modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);

		/*
		 * Also save ft and gt (only up to size slen).
		 */
		if (u < slen)
		{
			falcon_modp_iNTT2_ext(fx, 1, igm, logn, p, p0i);
			falcon_modp_iNTT2_ext(gx, 1, igm, logn, p, p0i);

			for (v = 0, x = ft + u, y = gt + u; v < n; v++, x += slen, y += slen)
			{
				*x = fx[v];
				*y = gx[v];
			}
		}
	}

	/*
	 * Rebuild f, g, F and G with the CRT. Note that the elements of F
	 * and G are consecutive, and thus can be rebuilt in a single
	 * loop; similarly, the elements of f and g are consecutive.
	 */
	falcon_zint_rebuild_CRT(Ft, llen, llen, n << 1, falcon_small_primes, 1, t1);
	falcon_zint_rebuild_CRT(ft, slen, slen, n << 1, falcon_small_primes, 1, t1);

	/*
	 * Here starts the Babai reduction, specialized for depth = 1.
	 *
	 * Candidates F and G (from Ft and Gt), and base f and g (ft and gt),
	 * are converted to floating point. There is no scaling, and a
	 * single pass is sufficient.
	 */

	 /*
	  * Convert F and G into floating point (rt1 and rt2).
	  */
	rt1 = falcon_align_fpr(tmp, gt + slen * n);
	rt2 = rt1 + n;
	falcon_poly_big_to_fp(rt1, Ft, llen, llen, logn);
	falcon_poly_big_to_fp(rt2, Gt, llen, llen, logn);

	/*
	 * Integer representation of F and G is no longer needed, we
	 * can remove it.
	 */
	qsc_memutils_move(tmp, ft, 2 * slen * n * sizeof(*ft));
	ft = tmp;
	gt = ft + slen * n;
	rt3 = falcon_align_fpr(tmp, gt + slen * n);
	qsc_memutils_move(rt3, rt1, 2 * n * sizeof(*rt1));
	rt1 = rt3;
	rt2 = rt1 + n;
	rt3 = rt2 + n;
	rt4 = rt3 + n;

	/*
	 * Convert f and g into floating point (rt3 and rt4).
	 */
	falcon_poly_big_to_fp(rt3, ft, slen, slen, logn);
	falcon_poly_big_to_fp(rt4, gt, slen, slen, logn);

	/*
	 * Remove unneeded ft and gt.
	 */
	qsc_memutils_move(tmp, rt1, 4 * n * sizeof(*rt1));
	rt1 = (falcon_fpr*)tmp;
	rt2 = rt1 + n;
	rt3 = rt2 + n;
	rt4 = rt3 + n;

	/*
	 * We now have:
	 *   rt1 = F
	 *   rt2 = G
	 *   rt3 = f
	 *   rt4 = g
	 * in that order in RAM. We convert all of them to FFT.
	 */
	falcon_FFT(rt1, logn);
	falcon_FFT(rt2, logn);
	falcon_FFT(rt3, logn);
	falcon_FFT(rt4, logn);

	/*
	 * Compute:
	 *   rt5 = F*adj(f) + G*adj(g)
	 *   rt6 = 1 / (f*adj(f) + g*adj(g))
	 * (Note that rt6 is half-length.)
	 */
	rt5 = rt4 + n;
	rt6 = rt5 + n;
	falcon_poly_add_muladj_fft(rt5, rt1, rt2, rt3, rt4, logn);
	falcon_poly_invnorm2_fft(rt6, rt3, rt4, logn);

	/*
	 * Compute:
	 *   rt5 = (F*adj(f)+G*adj(g)) / (f*adj(f)+g*adj(g))
	 */
	falcon_poly_mul_autoadj_fft(rt5, rt6, logn);

	/*
	 * Compute k as the rounded version of rt5. Check that none of
	 * the values is larger than 2^63-1 (in absolute value)
	 * because that would make the falcon_fpr_rint() do something undefined
	 * note that any out-of-bounds value here implies a failure and
	 * (f,g) will be discarded, so we can make a simple test.
	 */
	falcon_iFFT(rt5, logn);

	for (u = 0; u < n; u++)
	{
		falcon_fpr z;

		z = rt5[u];

		if (falcon_fpr_lt(z, falcon_fpr_ptwo63m1) == 0 || falcon_fpr_lt(falcon_fpr_mtwo63m1, z) == 0)
		{
			return 0;
		}

		rt5[u] = falcon_fpr_of(falcon_fpr_rint(z));
	}

	falcon_FFT(rt5, logn);

	/*
	 * Subtract k*f from F, and k*g from G.
	 */
	falcon_poly_mul_fft(rt3, rt5, logn);
	falcon_poly_mul_fft(rt4, rt5, logn);
	falcon_poly_sub(rt1, rt3, logn);
	falcon_poly_sub(rt2, rt4, logn);
	falcon_iFFT(rt1, logn);
	falcon_iFFT(rt2, logn);

	/*
	 * Convert back F and G to integers, and return.
	 */
	Ft = tmp;
	Gt = Ft + n;
	rt3 = falcon_align_fpr(tmp, Gt + n);
	qsc_memutils_move(rt3, rt1, 2 * n * sizeof(*rt1));
	rt1 = rt3;
	rt2 = rt1 + n;

	for (u = 0; u < n; ++u)
	{
		Ft[u] = (uint32_t)falcon_fpr_rint(rt1[u]);
		Gt[u] = (uint32_t)falcon_fpr_rint(rt2[u]);
	}

	return 1;
}

static int32_t falcon_solve_NTRU_binary_depth0(uint32_t logn, const int8_t* f, const int8_t* g, uint32_t* tmp)
{
	/*
	* Solving the NTRU equation, top level. Upon entry, the F and G
	* from the previous level should be in the tmp[] array.
	*
	* Returned value: 1 on success, 0 on error.
	*/

	falcon_fpr* rt2;
	falcon_fpr* rt3;
	size_t n;
	size_t hn;
	size_t u;
	uint32_t p;
	uint32_t p0i;
	uint32_t R2;
	uint32_t* Fp;
	uint32_t* Gp;
	uint32_t* t1;
	uint32_t* t2;
	uint32_t* t3;
	uint32_t* t4;
	uint32_t* t5;
	uint32_t* gm;
	uint32_t* igm;
	uint32_t* ft;
	uint32_t* gt;

	n = (size_t)1 << logn;
	hn = n >> 1;

	/*
	 * Equations are:
	 *
	 *   f' = f0^2 - X^2*f1^2
	 *   g' = g0^2 - X^2*g1^2
	 *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
	 *   F = F'*(g0 - X*g1)
	 *   G = G'*(f0 - X*f1)
	 *
	 * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
	 * degree N/2 (their odd-indexed coefficients are all zero).
	 *
	 * Everything should fit in 31-bit integers, hence we can just use
	 * the first small prime p = 2147473409.
	 */
	p = falcon_small_primes[0].p;
	p0i = falcon_modp_ninv31(p);
	R2 = falcon_modp_R2(p, p0i);

	Fp = tmp;
	Gp = Fp + hn;
	ft = Gp + hn;
	gt = ft + n;
	gm = gt + n;
	igm = gm + n;

	falcon_modp_mkgm2(gm, igm, logn, falcon_small_primes[0].g, p, p0i);

	/*
	 * Convert F' anf G' in NTT representation.
	 */
	for (u = 0; u < hn; ++u)
	{
		Fp[u] = falcon_modp_set(falcon_zint_one_to_plain(Fp + u), p);
		Gp[u] = falcon_modp_set(falcon_zint_one_to_plain(Gp + u), p);
	}

	falcon_modp_NTT2_ext(Fp, 1, gm, logn - 1, p, p0i);
	falcon_modp_NTT2_ext(Gp, 1, gm, logn - 1, p, p0i);

	/*
	 * Load f and g and convert them to NTT representation.
	 */
	for (u = 0; u < n; ++u)
	{
		ft[u] = falcon_modp_set(f[u], p);
		gt[u] = falcon_modp_set(g[u], p);
	}

	falcon_modp_NTT2_ext(ft, 1, gm, logn, p, p0i);
	falcon_modp_NTT2_ext(gt, 1, gm, logn, p, p0i);

	/*
	 * Build the unreduced F,G in ft and gt.
	 */
	for (u = 0; u < n; u += 2)
	{
		uint32_t ftA;
		uint32_t ftB;
		uint32_t gtA;
		uint32_t gtB;
		uint32_t mFp;
		uint32_t mGp;

		ftA = ft[u];
		ftB = ft[u + 1];
		gtA = gt[u];
		gtB = gt[u + 1];
		mFp = falcon_modp_montymul(Fp[u >> 1], R2, p, p0i);
		mGp = falcon_modp_montymul(Gp[u >> 1], R2, p, p0i);
		ft[u] = falcon_modp_montymul(gtB, mFp, p, p0i);
		ft[u + 1] = falcon_modp_montymul(gtA, mFp, p, p0i);
		gt[u] = falcon_modp_montymul(ftB, mGp, p, p0i);
		gt[u + 1] = falcon_modp_montymul(ftA, mGp, p, p0i);
	}

	falcon_modp_iNTT2_ext(ft, 1, igm, logn, p, p0i);
	falcon_modp_iNTT2_ext(gt, 1, igm, logn, p, p0i);

	Gp = Fp + n;
	t1 = Gp + n;
	qsc_memutils_move(Fp, ft, 2 * n * sizeof(*ft));

	/*
	 * We now need to apply the Babai reduction. At that point,
	 * we have F and G in two n-word arrays.
	 *
	 * We can compute F*adj(f)+G*adj(g) and f*adj(f)+g*adj(g)
	 * modulo p, using the NTT. We still move memory around in
	 * order to save RAM.
	 */
	t2 = t1 + n;
	t3 = t2 + n;
	t4 = t3 + n;
	t5 = t4 + n;

	/*
	 * Compute the NTT tables in t1 and t2. We do not keep t2
	 * (we'll recompute it later on).
	 */
	falcon_modp_mkgm2(t1, t2, logn, falcon_small_primes[0].g, p, p0i);

	/*
	 * Convert F and G to NTT.
	 */
	falcon_modp_NTT2_ext(Fp, 1, t1, logn, p, p0i);
	falcon_modp_NTT2_ext(Gp, 1, t1, logn, p, p0i);

	/*
	 * Load f and adj(f) in t4 and t5, and convert them to NTT
	 * representation.
	 */
	t4[0] = t5[0] = falcon_modp_set(f[0], p);

	for (u = 1; u < n; ++u)
	{
		t4[u] = falcon_modp_set(f[u], p);
		t5[n - u] = falcon_modp_set(-f[u], p);
	}

	falcon_modp_NTT2_ext(t4, 1, t1, logn, p, p0i);
	falcon_modp_NTT2_ext(t5, 1, t1, logn, p, p0i);

	/*
	 * Compute F*adj(f) in t2, and f*adj(f) in t3.
	 */
	for (u = 0; u < n; ++u)
	{
		uint32_t w;

		w = falcon_modp_montymul(t5[u], R2, p, p0i);
		t2[u] = falcon_modp_montymul(w, Fp[u], p, p0i);
		t3[u] = falcon_modp_montymul(w, t4[u], p, p0i);
	}

	/*
	 * Load g and adj(g) in t4 and t5, and convert them to NTT
	 * representation.
	 */
	t4[0] = t5[0] = falcon_modp_set(g[0], p);

	for (u = 1; u < n; ++u)
	{
		t4[u] = falcon_modp_set(g[u], p);
		t5[n - u] = falcon_modp_set(-g[u], p);
	}

	falcon_modp_NTT2_ext(t4, 1, t1, logn, p, p0i);
	falcon_modp_NTT2_ext(t5, 1, t1, logn, p, p0i);

	/*
	 * Add G*adj(g) to t2, and g*adj(g) to t3.
	 */
	for (u = 0; u < n; ++u)
	{
		uint32_t w;

		w = falcon_modp_montymul(t5[u], R2, p, p0i);
		t2[u] = falcon_modp_add(t2[u], falcon_modp_montymul(w, Gp[u], p, p0i), p);
		t3[u] = falcon_modp_add(t3[u], falcon_modp_montymul(w, t4[u], p, p0i), p);
	}

	/*
	 * Convert back t2 and t3 to normal representation (normalized
	 * around 0), and then
	 * move them to t1 and t2. We first need to recompute the
	 * inverse table for NTT.
	 */
	falcon_modp_mkgm2(t1, t4, logn, falcon_small_primes[0].g, p, p0i);
	falcon_modp_iNTT2_ext(t2, 1, t4, logn, p, p0i);
	falcon_modp_iNTT2_ext(t3, 1, t4, logn, p, p0i);

	for (u = 0; u < n; ++u)
	{
		t1[u] = (uint32_t)falcon_modp_norm(t2[u], p);
		t2[u] = (uint32_t)falcon_modp_norm(t3[u], p);
	}

	/*
	 * At that point, array contents are:
	 *
	 *   F (NTT representation) (Fp)
	 *   G (NTT representation) (Gp)
	 *   F*adj(f)+G*adj(g) (t1)
	 *   f*adj(f)+g*adj(g) (t2)
	 *
	 * We want to divide t1 by t2. The result is not integral; it
	 * must be rounded. We thus need to use the FFT.
	 */

	 /*
	  * Get f*adj(f)+g*adj(g) in FFT representation. Since this
	  * polynomial is auto-adjoint, all its coordinates in FFT
	  * representation are actually real, so we can truncate off
	  * the imaginary parts.
	  */
	rt3 = falcon_align_fpr(tmp, t3);

	for (u = 0; u < n; ++u)
	{
		rt3[u] = falcon_fpr_of(((int32_t *)t2)[u]);
	}

	falcon_FFT(rt3, logn);
	rt2 = falcon_align_fpr(tmp, t2);
	qsc_memutils_move(rt2, rt3, hn * sizeof(*rt3));

	/*
	 * Convert F*adj(f)+G*adj(g) in FFT representation.
	 */
	rt3 = rt2 + hn;

	for (u = 0; u < n; ++u)
	{
		rt3[u] = falcon_fpr_of(((int32_t *)t1)[u]);
	}

	falcon_FFT(rt3, logn);

	/*
	 * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) and get
	 * its rounded normal representation in t1.
	 */
	falcon_poly_div_autoadj_fft(rt3, rt2, logn);
	falcon_iFFT(rt3, logn);

	for (u = 0; u < n; ++u)
	{
		t1[u] = falcon_modp_set((int32_t)falcon_fpr_rint(rt3[u]), p);
	}

	/*
	 * RAM contents are now:
	 *
	 *   F (NTT representation) (Fp)
	 *   G (NTT representation) (Gp)
	 *   k (t1)
	 *
	 * We want to compute F-k*f, and G-k*g.
	 */
	t2 = t1 + n;
	t3 = t2 + n;
	t4 = t3 + n;
	t5 = t4 + n;
	falcon_modp_mkgm2(t2, t3, logn, falcon_small_primes[0].g, p, p0i);

	for (u = 0; u < n; u++)
	{
		t4[u] = falcon_modp_set(f[u], p);
		t5[u] = falcon_modp_set(g[u], p);
	}

	falcon_modp_NTT2_ext(t1, 1, t2, logn, p, p0i);
	falcon_modp_NTT2_ext(t4, 1, t2, logn, p, p0i);
	falcon_modp_NTT2_ext(t5, 1, t2, logn, p, p0i);

	for (u = 0; u < n; u++)
	{
		uint32_t kw;

		kw = falcon_modp_montymul(t1[u], R2, p, p0i);
		Fp[u] = falcon_modp_sub(Fp[u], falcon_modp_montymul(kw, t4[u], p, p0i), p);
		Gp[u] = falcon_modp_sub(Gp[u], falcon_modp_montymul(kw, t5[u], p, p0i), p);
	}

	falcon_modp_iNTT2_ext(Fp, 1, t3, logn, p, p0i);
	falcon_modp_iNTT2_ext(Gp, 1, t3, logn, p, p0i);

	for (u = 0; u < n; ++u)
	{
		Fp[u] = (uint32_t)falcon_modp_norm(Fp[u], p);
		Gp[u] = (uint32_t)falcon_modp_norm(Gp[u], p);
	}

	return 1;
}

static int32_t falcon_solve_NTRU(uint32_t logn, int8_t *F, int8_t *G, const int8_t *f, const int8_t *g, int32_t lim, uint32_t *tmp)
{
	/*
	* Solve the NTRU equation. Returned value is 1 on success, 0 on error.
	* G can be NULL, in which case that value is computed but not returned.
	* If any of the coefficients of F and G exceeds lim (in absolute value),
	* then 0 is returned.
	*/

	size_t n;
	size_t u;
	uint32_t* ft;
	uint32_t* gt;
	uint32_t* Ft;
	uint32_t* Gt;
	uint32_t* gm;
	uint32_t p;
	uint32_t p0i;
	uint32_t r;
	const falcon_small_prime* primes;

	n = falcon_mkn(logn);

	if (falcon_solve_NTRU_deepest(logn, f, g, tmp) == 0)
	{
		return 0;
	}

	/*
	 * For logn <= 2, we need to use falcon_solve_NTRU_intermediate()
	 * directly, because coefficients are a bit too large and
	 * do not fit the hypotheses in falcon_solve_NTRU_binary_depth0().
	 */
	if (logn <= 2)
	{
		uint32_t depth;

		depth = logn;

		while (depth-- > 0)
		{
			if (falcon_solve_NTRU_intermediate(logn, f, g, depth, tmp) == 0)
			{
				return 0;
			}
		}
	}
	else
	{
		uint32_t depth;

		depth = logn;

		while (depth-- > 2)
		{
			if (falcon_solve_NTRU_intermediate(logn, f, g, depth, tmp) == 0)
			{
				return 0;
			}
		}

		if (falcon_solve_NTRU_binary_depth1(logn, f, g, tmp) == 0)
		{
			return 0;
		}

		if (falcon_solve_NTRU_binary_depth0(logn, f, g, tmp) == 0)
		{
			return 0;
		}
	}

	/*
	 * If no buffer has been provided for G, use a temporary one.
	 */
	if (G == NULL)
	{
		G = (int8_t*)(tmp + 2 * n);
	}

	/*
	 * Final F and G are in fk->tmp, one word per coefficient
	 * (signed value over 31 bits).
	 */
	if (falcon_poly_big_to_small(F, tmp, lim, logn) == 0 || falcon_poly_big_to_small(G, tmp + n, lim, logn) == 0)
	{
		return 0;
	}

	/*
	 * Verify that the NTRU equation is fulfilled. Since all elements
	 * have short lengths, verifying modulo a small prime p works, and
	 * allows using the NTT.
	 *
	 * We put Gt[] first in tmp[], and process it first, so that it does
	 * not overlap with G[] in case we allocated it ourselves.
	 */
	Gt = tmp;
	ft = Gt + n;
	gt = ft + n;
	Ft = gt + n;
	gm = Ft + n;

	primes = falcon_small_primes;
	p = primes[0].p;
	p0i = falcon_modp_ninv31(p);
	falcon_modp_mkgm2(gm, tmp, logn, primes[0].g, p, p0i);

	for (u = 0; u < n; ++u)
	{
		Gt[u] = falcon_modp_set(G[u], p);
	}

	for (u = 0; u < n; ++u)
	{
		ft[u] = falcon_modp_set(f[u], p);
		gt[u] = falcon_modp_set(g[u], p);
		Ft[u] = falcon_modp_set(F[u], p);
	}

	falcon_modp_NTT2_ext(ft, 1, gm, logn, p, p0i);
	falcon_modp_NTT2_ext(gt, 1, gm, logn, p, p0i);
	falcon_modp_NTT2_ext(Ft, 1, gm, logn, p, p0i);
	falcon_modp_NTT2_ext(Gt, 1, gm, logn, p, p0i);
	r = falcon_modp_montymul(12289, 1, p, p0i);

	for (u = 0; u < n; ++u)
	{
		uint32_t z;

		z = falcon_modp_sub(falcon_modp_montymul(ft[u], Gt[u], p, p0i), falcon_modp_montymul(gt[u], Ft[u], p, p0i), p);

		if (z != r)
		{
			return 0;
		}
	}

	return 1;
}

static void falcon_poly_small_mkgauss(qsc_keccak_state* kctx, int8_t* f, uint32_t logn)
{
	/*
	* Generate a random polynomial with a Gaussian distribution. This function
	* also makes sure that the resultant of the polynomial with phi is odd.
	*/

	size_t n;
	size_t u;
	uint32_t mod2;
	int32_t s;

	n = falcon_mkn(logn);
	mod2 = 0;

	for (u = 0; u < n; ++u)
	{
		while (true)
		{
			s = falcon_mkgauss(kctx, logn);

			/*
			 * We need the coefficient to fit within -127..+127
			 * realistically, this is always the case except for
			 * the very low degrees (N = 2 or 4), for which there
			 * is no real security anyway.
			 */
			if (s < -127 || s > 127)
			{
				continue;
			}

			/*
			 * We need the sum of all coefficients to be 1; otherwise,
			 * the resultant of the polynomial with X^N+1 will be even,
			 * and the binary GCD will fail.
			 */
			if (u == n - 1)
			{
				if ((mod2 ^ (uint32_t)(s & 1)) == 0)
				{
					continue;
				}
			}
			else
			{
				mod2 ^= (uint32_t)(s & 1);
			}

			f[u] = (int8_t)s;
			break;
		}
	}
}

static void falcon_keygen(qsc_keccak_state* kctx, int8_t* f, int8_t* g, int8_t* F, int8_t* G, uint16_t* h, uint32_t logn, uint8_t* tmp)
{
	/*
	 * Algorithm is the following:
	 *
	 *  - Generate f and g with the Gaussian distribution.
	 *
	 *  - If either Res(f,phi) or Res(g,phi) is even, try again.
	 *
	 *	  if ||(f,g)|| is too large, try again.
	 *
	 *    if ||B~_{f,g}|| is too large, try again.
	 *
	 *    if f is not invertible mod phi mod q, try again.
	 *
	 *  - Compute h = g/f mod phi mod q.
	 *
	 *  - Solve the NTRU equation fG - gF = q; if the solving fails,
	 *    try again. Usual failure condition is when Res(f,phi)
	 *    and Res(g,phi) are not prime to each other.
	 */
	size_t n;
	size_t u;
	uint16_t* h2;
	uint16_t* tmp2;

	n = falcon_mkn(logn);

	/*
	 * We need to generate f and g randomly, until we find values
	 * such that the norm of (g,-f), and of the orthogonalized
	 * vector, are satisfying. The orthogonalized vector is:
	 *   (q*adj(f)/(f*adj(f)+g*adj(g)), q*adj(g)/(f*adj(f)+g*adj(g)))
	 * (it is actually the (N+1)-th row of the Gram-Schmidt basis).
	 *
	 * In the binary case, coefficients of f and g are generated
	 * independently of each other, with a discrete Gaussian
	 * distribution of standard deviation 1.17*sqrt(q/(2*N)). Then,
	 * the two vectors have expected norm 1.17*sqrt(q), which is
	 * also our acceptance bound: we require both vectors to be no
	 * larger than that (this will be satisfied about 1/4th of the
	 * time, thus we expect sampling new (f,g) about 4 times for that
	 * step).
	 *
	 * We require that Res(f,phi) and Res(g,phi) are both odd (the
	 * NTRU equation solver requires it).
	 */
	for (;;)
	{
		falcon_fpr* rt1;
		falcon_fpr* rt2;
		falcon_fpr* rt3;
		falcon_fpr bnorm;
		uint32_t normf;
		uint32_t normg;
		uint32_t norm;
		int32_t lim;

		/*
		 * The falcon_poly_small_mkgauss() function makes sure
		 * that the sum of coefficients is 1 modulo 2
		 * (i.e. the resultant of the polynomial with phi
		 * will be odd).
		 */
		falcon_poly_small_mkgauss(kctx, f, logn);
		falcon_poly_small_mkgauss(kctx, g, logn);

		/*
		 * Verify that all coefficients are within the bounds
		 * defined in max_fg_bits. This is the case with
		 * overwhelming probability; this guarantees that the
		 * key will be encodable with FALCON_COMP_TRIM.
		 */
		lim = 1UL << (falcon_max_fg_bits[logn] - 1);

		for (u = 0; u < n; ++u)
		{
			/*
			 * We can use non-CT tests since on any failure
			 * we will discard f and g.
			 */
			if (f[u] >= lim || f[u] <= -lim || g[u] >= lim || g[u] <= -lim)
			{
				lim = -1;
				break;
			}
		}

		if (lim < 0)
		{
			continue;
		}

		/*
		 * Bound is 1.17*sqrt(q). We compute the squared
		 * norms. With q = 12289, the squared bound is:
		 *   (1.17^2)* 12289 = 16822.4121
		 * Since f and g are integral, the squared norm
		 * of (g,-f) is an integer.
		 */
		normf = falcon_poly_small_sqnorm(f, logn);
		normg = falcon_poly_small_sqnorm(g, logn);
		norm = (normf + normg) | (uint32_t)-(int32_t)((normf | normg) >> 31);

		if (norm >= 16823)
		{
			continue;
		}

		/*
		 * We compute the orthogonalized vector norm.
		 */
		rt1 = (falcon_fpr *)tmp;
		rt2 = rt1 + n;
		rt3 = rt2 + n;
		falcon_poly_small_to_fp(rt1, f, logn);
		falcon_poly_small_to_fp(rt2, g, logn);
		falcon_FFT(rt1, logn);
		falcon_FFT(rt2, logn);
		falcon_poly_invnorm2_fft(rt3, rt1, rt2, logn);
		falcon_poly_adj_fft(rt1, logn);
		falcon_poly_adj_fft(rt2, logn);
		falcon_poly_mulconst(rt1, falcon_fpr_q, logn);
		falcon_poly_mulconst(rt2, falcon_fpr_q, logn);
		falcon_poly_mul_autoadj_fft(rt1, rt3, logn);
		falcon_poly_mul_autoadj_fft(rt2, rt3, logn);
		falcon_iFFT(rt1, logn);
		falcon_iFFT(rt2, logn);
		bnorm = falcon_fpr_zero;

		for (u = 0; u < n; ++u)
		{
			bnorm = falcon_fpr_add(bnorm, falcon_fpr_sqr(rt1[u]));
			bnorm = falcon_fpr_add(bnorm, falcon_fpr_sqr(rt2[u]));
		}

		if (falcon_fpr_lt(bnorm, falcon_fpr_bnorm_max) == 0)
		{
			continue;
		}

		/*
		 * Compute public key h = g/f mod X^N+1 mod q. If this
		 * fails, we must restart.
		 */
		if (h == NULL)
		{
			h2 = (uint16_t *)tmp;
			tmp2 = h2 + n;
		}
		else
		{
			h2 = h;
			tmp2 = (uint16_t *)tmp;
		}

		if (falcon_compute_public(h2, f, g, logn, (uint8_t*)tmp2) == 0)
		{
			continue;
		}

		/*
		 * Solve the NTRU equation to get F and G.
		 */
		lim = (1UL << (uint32_t)(falcon_max_FG_bits[logn] - 1)) - 1;

		if (falcon_solve_NTRU(logn, F, G, f, g, lim, (uint32_t*)tmp) == 0)
		{
			continue;
		}

		/*
		 * Key pair is generated.
		 */
		break;
	}
}

/* sign.c */

#if defined(FALCON_HISTORICAL_ENABLE)

static void falcon_poly_LDLmv_fft(falcon_fpr* restrict d11, falcon_fpr* restrict l10, const falcon_fpr* restrict g00, const falcon_fpr* restrict g01, const falcon_fpr* restrict g11, uint32_t logn)
{
	size_t hn;
	size_t n;
	size_t u;

	n = (size_t)1 << logn;
	hn = n >> 1;

	for (u = 0; u < hn; ++u)
	{
		falcon_fpr g00_re;
		falcon_fpr g00_im;
		falcon_fpr g01_re;
		falcon_fpr g01_im;
		falcon_fpr g11_re;
		falcon_fpr g11_im;
		falcon_fpr mu_re;
		falcon_fpr mu_im;

		g00_re = g00[u];
		g00_im = g00[u + hn];
		g01_re = g01[u];
		g01_im = g01[u + hn];
		g11_re = g11[u];
		g11_im = g11[u + hn];
		falcon_fpc_div(&mu_re, &mu_im, g01_re, g01_im, g00_re, g00_im);
		falcon_fpc_mul(&g01_re, &g01_im, mu_re, mu_im, g01_re, falcon_fpr_neg(g01_im));
		falcon_fpc_sub(&d11[u], &d11[u + hn], g11_re, g11_im, g01_re, g01_im);
		l10[u] = mu_re;
		l10[u + hn] = falcon_fpr_neg(mu_im);
	}
}

static uint32_t falcon_ffLDL_treesize(uint32_t logn)
{
	/*
	* Get the size of the LDL tree for an input with polynomials of size
	* 2^logn. The size is expressed in the number of elements.
	* For logn = 0 (polynomials are constant), the "tree" is a
	* single element. Otherwise, the tree node has size 2^logn, and
	* has two child trees for size logn-1 each. Thus, treesize s()
	* must fulfill these two relations:
	*
	*   s(0) = 1
	*   s(logn) = (2^logn) + 2*s(logn-1)
	*/

	return (logn + 1) << logn;
}

static size_t falcon_skoff_b00(uint32_t logn)
{
	(void)logn;
	return 0;
}

static size_t falcon_skoff_b01(uint32_t logn)
{
	return falcon_mkn(logn);
}

static size_t falcon_skoff_b10(uint32_t logn)
{
	return 2 * falcon_mkn(logn);
}

static size_t falcon_skoff_b11(uint32_t logn)
{
	return 3 * falcon_mkn(logn);
}

static size_t falcon_skoff_tree(uint32_t logn)
{
	return 4 * falcon_mkn(logn);
}

static void falcon_ffLDL_fft_inner(falcon_fpr* restrict tree, falcon_fpr* restrict g0, falcon_fpr* restrict g1, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	 * Inner function for falcon_ffLDL_fft(). It expects the matrix to be both
	 * auto-adjoint and quasicyclic; also, it uses the source operands
	 * as modifiable temporaries.
	 *
	 * tmp[] must have room for at least one polynomial.
	 */

	size_t hn;
	size_t n;

	n = falcon_mkn(logn);

	if (n == 1)
	{
		tree[0] = g0[0];
		return;
	}

	hn = n >> 1;

	/*
	 * The LDL decomposition yields L (which is written in the tree)
	 * and the diagonal of D. Since d00 = g0, we just write d11
	 * into tmp.
	 */
	falcon_poly_LDLmv_fft(tmp, tree, g0, g1, g0, logn);

	/*
	 * Split d00 (currently in g0) and d11 (currently in tmp). We
	 * reuse g0 and g1 as temporary storage spaces:
	 *   d00 splits into g1, g1+hn
	 *   d11 splits into g0, g0+hn
	 */
	falcon_poly_split_fft(g1, g1 + hn, g0, logn);
	falcon_poly_split_fft(g0, g0 + hn, tmp, logn);

	/*
	 * Each split result is the first row of a new auto-adjoint
	 * quasicyclic matrix for the next recursive step.
	 */
	falcon_ffLDL_fft_inner(tree + n, g1, g1 + hn, logn - 1, tmp);
	falcon_ffLDL_fft_inner(tree + n + falcon_ffLDL_treesize(logn - 1), g0, g0 + hn, logn - 1, tmp);
}

static void falcon_ffLDL_fft(falcon_fpr* restrict tree, const falcon_fpr* restrict g00, const falcon_fpr* restrict g01, const falcon_fpr* restrict g11, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	 * Compute the ffLDL tree of an auto-adjoint matrix G. The matrix
	 * is provided as three polynomials (FFT representation).
	 *
	 * The "tree" array is filled with the computed tree, of size
	 * (logn+1)*(2^logn) elements (see falcon_ffLDL_treesize()).
	 *
	 * Input arrays MUST NOT overlap, except possibly the three unmodified
	 * arrays g00, g01 and g11. tmp[] should have room for at least three
	 * polynomials of 2^logn elements each.
	 */

	falcon_fpr* d00;
	falcon_fpr* d11;
	size_t hn;
	size_t n;

	n = falcon_mkn(logn);

	if (n == 1)
	{
		tree[0] = g00[0];
		return;
	}

	hn = n >> 1;
	d00 = tmp;
	d11 = tmp + n;
	tmp += n << 1;

	qsc_memutils_copy(d00, g00, n * sizeof(*g00));
	falcon_poly_LDLmv_fft(d11, tree, g00, g01, g11, logn);

	falcon_poly_split_fft(tmp, tmp + hn, d00, logn);
	falcon_poly_split_fft(d00, d00 + hn, d11, logn);
	qsc_memutils_copy(d11, tmp, n * sizeof(*tmp));
	falcon_ffLDL_fft_inner(tree + n, d11, d11 + hn, logn - 1, tmp);
	falcon_ffLDL_fft_inner(tree + n + falcon_ffLDL_treesize(logn - 1), d00, d00 + hn, logn - 1, tmp);
}

static void falcon_ffLDL_binary_normalize(falcon_fpr* tree, uint32_t orig_logn, uint32_t logn)
{
	/*
	* Normalize an ffLDL tree: each leaf of value x is replaced with
	* sigma / sqrt(x).
	*/

	size_t n;

	n = falcon_mkn(logn);
	if (n == 1)
	{
		/*
		 * We actually store in the tree leaf the inverse of
		 * the value mandated by the specification: this
		 * saves a division both here and in the sampler.
		 */
		tree[0] = falcon_fpr_mul(falcon_fpr_sqrt(tree[0]), falcon_fpr_inv_sigma[orig_logn]);
	}
	else
	{
		falcon_ffLDL_binary_normalize(tree + n, orig_logn, logn - 1);
		falcon_ffLDL_binary_normalize(tree + n + falcon_ffLDL_treesize(logn - 1), orig_logn, logn - 1);
	}
}

static void falcon_prng_get_bytes(falcon_prng_state* pctx, void* dst, size_t len)
{
	uint8_t* buf;

	buf = dst;

	while (len > 0)
	{
		size_t clen;

		clen = sizeof(pctx->buf) - pctx->ptr;

		if (clen > len)
		{
			clen = len;
		}

		qsc_memutils_copy(buf, pctx->buf, clen);
		buf += clen;
		len -= clen;
		pctx->ptr += clen;

		if (pctx->ptr == sizeof(pctx->buf))
		{
			falcon_prng_refill(pctx);
		}
	}
}

static int32_t falcon_do_sign_tree(falcon_samplerZ samp, void* samp_ctx, int16_t* s2, const falcon_fpr* restrict expanded_key,
	const uint16_t* hm, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	* Compute a signature: the signature contains two vectors, s1 and s2.
	* The s1 vector is not returned. The squared norm of (s1,s2) is
	* computed, and if it is short enough, then s2 is returned into the
	* s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is
	* returned; the caller should then try again. This function uses an
	* expanded key.
	*
	* tmp[] must have room for at least six polynomials.
	*/

	const falcon_fpr* b00;
	const falcon_fpr* b01;
	const falcon_fpr* b10;
	const falcon_fpr* b11;
	const falcon_fpr* tree;
	falcon_fpr* t0;
	falcon_fpr* t1;
	falcon_fpr* tx;
	falcon_fpr* ty;
	falcon_fpr ni;
	size_t n;
	size_t u;
	uint32_t sqn;
	uint32_t ng;
	int16_t* s1tmp;
	int16_t* s2tmp;

	n = falcon_mkn(logn);
	t0 = tmp;
	t1 = t0 + n;
	b00 = expanded_key + falcon_skoff_b00(logn);
	b01 = expanded_key + falcon_skoff_b01(logn);
	b10 = expanded_key + falcon_skoff_b10(logn);
	b11 = expanded_key + falcon_skoff_b11(logn);
	tree = expanded_key + falcon_skoff_tree(logn);

	/*
	 * Set the target vector to [hm, 0] (hm is the hashed message).
	 */
	for (u = 0; u < n; ++u)
	{
		t0[u] = falcon_fpr_of(hm[u]);
	}

	/*
	 * Apply the lattice basis to obtain the real target
	 * vector (after normalization with regards to modulus).
	 */
	falcon_FFT(t0, logn);
	ni = falcon_fpr_inverse_of_q;
	qsc_memutils_copy(t1, t0, n * sizeof(*t0));
	falcon_poly_mul_fft(t1, b01, logn);
	falcon_poly_mulconst(t1, falcon_fpr_neg(ni), logn);
	falcon_poly_mul_fft(t0, b11, logn);
	falcon_poly_mulconst(t0, ni, logn);

	tx = t1 + n;
	ty = tx + n;

	/*
	 * Apply sampling. Output is written back in [tx, ty].
	 */
	falcon_ffSampling_fft(samp, samp_ctx, tx, ty, tree, t0, t1, logn, ty + n);

	/*
	 * Get the lattice point corresponding to that tiny vector.
	 */
	qsc_memutils_copy(t0, tx, n * sizeof(*tx));
	qsc_memutils_copy(t1, ty, n * sizeof(*ty));
	falcon_poly_mul_fft(tx, b00, logn);
	falcon_poly_mul_fft(ty, b10, logn);
	falcon_poly_add(tx, ty, logn);
	qsc_memutils_copy(ty, t0, n * sizeof(*t0));
	falcon_poly_mul_fft(ty, b01, logn);

	qsc_memutils_copy(t0, tx, n * sizeof(*tx));
	falcon_poly_mul_fft(t1, b11, logn);
	falcon_poly_add(t1, ty, logn);

	falcon_iFFT(t0, logn);
	falcon_iFFT(t1, logn);

	/*
	 * Compute the signature.
	 */
	s1tmp = (int16_t*)tx;
	sqn = 0;
	ng = 0;

	for (u = 0; u < n; ++u)
	{
		int32_t z;

		z = (int32_t)hm[u] - (int32_t)falcon_fpr_rint(t0[u]);
		sqn += (uint32_t)(z * z);
		ng |= sqn;
		s1tmp[u] = (int16_t)z;
	}

	sqn |= (uint32_t)-(int32_t)(ng >> 31);

	/*
	 * With "normal" degrees (e.g. 512 or 1024), it is very
	 * improbable that the computed vector is not short enough
	 * however, it may happen in practice for the very reduced
	 * versions (e.g. degree 16 or below). In that case, the caller
	 * will loop, and we must not write anything into s2[] because
	 * s2[] may overlap with the hashed message hm[] and we need
	 * hm[] for the next iteration.
	 */
	s2tmp = (int16_t *)tmp;

	for (u = 0; u < n; ++u)
	{
		s2tmp[u] = (int16_t)-falcon_fpr_rint(t1[u]);
	}

	if (falcon_is_short_half(sqn, s2tmp, logn) != 0)
	{
		qsc_memutils_copy(s2, s2tmp, n * sizeof(*s2));
		qsc_memutils_copy(tmp, s1tmp, n * sizeof(*s1tmp));

		return 1;
	}

	return 0;
}


static void falcon_ffSampling_fft(falcon_samplerZ samp, void* samp_ctx, falcon_fpr* restrict z0, falcon_fpr* restrict z1, const falcon_fpr* restrict tree,
	const falcon_fpr* restrict t0, const falcon_fpr* restrict t1, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	* Perform Fast Fourier Sampling for target vector t and LDL tree T.
	* tmp[] must have size for at least two polynomials of size 2^logn.
	*/

	size_t hn;
	size_t n;
	const falcon_fpr* tree0;
	const falcon_fpr* tree1;

	/*
	 * When logn == 2, we inline the last two recursion levels.
	 */
	if (logn == 2)
	{
		falcon_fpr x0;
		falcon_fpr x1;
		falcon_fpr y0;
		falcon_fpr y1;
		falcon_fpr w0;
		falcon_fpr w1;
		falcon_fpr w2;
		falcon_fpr w3;
		falcon_fpr sigma;
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;
		falcon_fpr c_re;
		falcon_fpr c_im;

		tree0 = tree + 4;
		tree1 = tree + 8;

		/*
		 * We split t1 into w*, then do the recursive invocation,
		 * with output in w*. We finally merge back into z1.
		 */
		a_re = t1[0];
		a_im = t1[2];
		b_re = t1[1];
		b_im = t1[3];
		c_re = falcon_fpr_add(a_re, b_re);
		c_im = falcon_fpr_add(a_im, b_im);
		w0 = falcon_fpr_half(c_re);
		w1 = falcon_fpr_half(c_im);
		c_re = falcon_fpr_sub(a_re, b_re);
		c_im = falcon_fpr_sub(a_im, b_im);
		w2 = falcon_fpr_mul(falcon_fpr_add(c_re, c_im), falcon_fpr_invsqrt8);
		w3 = falcon_fpr_mul(falcon_fpr_sub(c_im, c_re), falcon_fpr_invsqrt8);

		x0 = w2;
		x1 = w3;
		sigma = tree1[3];
		w2 = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		w3 = falcon_fpr_of(samp(samp_ctx, x1, sigma));
		a_re = falcon_fpr_sub(x0, w2);
		a_im = falcon_fpr_sub(x1, w3);
		b_re = tree1[0];
		b_im = tree1[1];
		c_re = falcon_fpr_sub(falcon_fpr_mul(a_re, b_re), falcon_fpr_mul(a_im, b_im));
		c_im = falcon_fpr_add(falcon_fpr_mul(a_re, b_im), falcon_fpr_mul(a_im, b_re));
		x0 = falcon_fpr_add(c_re, w0);
		x1 = falcon_fpr_add(c_im, w1);
		sigma = tree1[2];
		w0 = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		w1 = falcon_fpr_of(samp(samp_ctx, x1, sigma));

		a_re = w0;
		a_im = w1;
		b_re = w2;
		b_im = w3;
		c_re = falcon_fpr_mul(falcon_fpr_sub(b_re, b_im), falcon_fpr_invsqrt2);
		c_im = falcon_fpr_mul(falcon_fpr_add(b_re, b_im), falcon_fpr_invsqrt2);
		z1[0] = w0 = falcon_fpr_add(a_re, c_re);
		z1[2] = w2 = falcon_fpr_add(a_im, c_im);
		z1[1] = w1 = falcon_fpr_sub(a_re, c_re);
		z1[3] = w3 = falcon_fpr_sub(a_im, c_im);

		/*
		 * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in w*.
		 */
		w0 = falcon_fpr_sub(t1[0], w0);
		w1 = falcon_fpr_sub(t1[1], w1);
		w2 = falcon_fpr_sub(t1[2], w2);
		w3 = falcon_fpr_sub(t1[3], w3);

		a_re = w0;
		a_im = w2;
		b_re = tree[0];
		b_im = tree[2];
		w0 = falcon_fpr_sub(falcon_fpr_mul(a_re, b_re), falcon_fpr_mul(a_im, b_im));
		w2 = falcon_fpr_add(falcon_fpr_mul(a_re, b_im), falcon_fpr_mul(a_im, b_re));
		a_re = w1;
		a_im = w3;
		b_re = tree[1];
		b_im = tree[3];
		w1 = falcon_fpr_sub(falcon_fpr_mul(a_re, b_re), falcon_fpr_mul(a_im, b_im));
		w3 = falcon_fpr_add(falcon_fpr_mul(a_re, b_im), falcon_fpr_mul(a_im, b_re));

		w0 = falcon_fpr_add(w0, t0[0]);
		w1 = falcon_fpr_add(w1, t0[1]);
		w2 = falcon_fpr_add(w2, t0[2]);
		w3 = falcon_fpr_add(w3, t0[3]);

		/*
		 * Second recursive invocation.
		 */
		a_re = w0;
		a_im = w2;
		b_re = w1;
		b_im = w3;
		c_re = falcon_fpr_add(a_re, b_re);
		c_im = falcon_fpr_add(a_im, b_im);
		w0 = falcon_fpr_half(c_re);
		w1 = falcon_fpr_half(c_im);
		c_re = falcon_fpr_sub(a_re, b_re);
		c_im = falcon_fpr_sub(a_im, b_im);
		w2 = falcon_fpr_mul(falcon_fpr_add(c_re, c_im), falcon_fpr_invsqrt8);
		w3 = falcon_fpr_mul(falcon_fpr_sub(c_im, c_re), falcon_fpr_invsqrt8);

		x0 = w2;
		x1 = w3;
		sigma = tree0[3];
		w2 = y0 = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		w3 = y1 = falcon_fpr_of(samp(samp_ctx, x1, sigma));
		a_re = falcon_fpr_sub(x0, y0);
		a_im = falcon_fpr_sub(x1, y1);
		b_re = tree0[0];
		b_im = tree0[1];
		c_re = falcon_fpr_sub(falcon_fpr_mul(a_re, b_re), falcon_fpr_mul(a_im, b_im));
		c_im = falcon_fpr_add(falcon_fpr_mul(a_re, b_im), falcon_fpr_mul(a_im, b_re));
		x0 = falcon_fpr_add(c_re, w0);
		x1 = falcon_fpr_add(c_im, w1);
		sigma = tree0[2];
		w0 = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		w1 = falcon_fpr_of(samp(samp_ctx, x1, sigma));

		a_re = w0;
		a_im = w1;
		b_re = w2;
		b_im = w3;
		c_re = falcon_fpr_mul(falcon_fpr_sub(b_re, b_im), falcon_fpr_invsqrt2);
		c_im = falcon_fpr_mul(falcon_fpr_add(b_re, b_im), falcon_fpr_invsqrt2);
		z0[0] = falcon_fpr_add(a_re, c_re);
		z0[2] = falcon_fpr_add(a_im, c_im);
		z0[1] = falcon_fpr_sub(a_re, c_re);
		z0[3] = falcon_fpr_sub(a_im, c_im);

		return;
	}

	/*
	 * Case logn == 1 is reachable only when using Falcon-2 (the
	 * smallest size for which Falcon is mathematically defined, but
	 * of course way too insecure to be of any use).
	 */
	if (logn == 1)
	{
		falcon_fpr x0;
		falcon_fpr x1;
		falcon_fpr y0;
		falcon_fpr y1;
		falcon_fpr sigma;
		falcon_fpr a_re;
		falcon_fpr a_im;
		falcon_fpr b_re;
		falcon_fpr b_im;
		falcon_fpr c_re;
		falcon_fpr c_im;

		x0 = t1[0];
		x1 = t1[1];
		sigma = tree[3];
		z1[0] = y0 = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		z1[1] = y1 = falcon_fpr_of(samp(samp_ctx, x1, sigma));
		a_re = falcon_fpr_sub(x0, y0);
		a_im = falcon_fpr_sub(x1, y1);
		b_re = tree[0];
		b_im = tree[1];
		c_re = falcon_fpr_sub(falcon_fpr_mul(a_re, b_re), falcon_fpr_mul(a_im, b_im));
		c_im = falcon_fpr_add(falcon_fpr_mul(a_re, b_im), falcon_fpr_mul(a_im, b_re));
		x0 = falcon_fpr_add(c_re, t0[0]);
		x1 = falcon_fpr_add(c_im, t0[1]);
		sigma = tree[2];
		z0[0] = falcon_fpr_of(samp(samp_ctx, x0, sigma));
		z0[1] = falcon_fpr_of(samp(samp_ctx, x1, sigma));

		return;
	}

	/*
	 * Normal end of recursion is for logn == 0. Since the last
	 * steps of the recursions were inlined in the blocks above
	 * (when logn == 1 or 2), this case is not reachable, and is
	 * retained here only for documentation purposes.
	 */

	 /*
	  * General recursive case (logn >= 3).
	  */

	n = (size_t)1 << logn;
	hn = n >> 1;
	tree0 = tree + n;
	tree1 = tree + n + falcon_ffLDL_treesize(logn - 1);

	/*
	 * We split t1 into z1 (reused as temporary storage), then do
	 * the recursive invocation, with output in tmp. We finally
	 * merge back into z1.
	 */
	falcon_poly_split_fft(z1, z1 + hn, t1, logn);
	falcon_ffSampling_fft(samp, samp_ctx, tmp, tmp + hn, tree1, z1, z1 + hn, logn - 1, tmp + n);
	falcon_poly_merge_fft(z1, tmp, tmp + hn, logn);

	/*
	 * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in tmp[].
	 */
	qsc_memutils_copy(tmp, t1, n * sizeof(*t1));
	falcon_poly_sub(tmp, z1, logn);
	falcon_poly_mul_fft(tmp, tree, logn);
	falcon_poly_add(tmp, t0, logn);

	/*
	 * Second recursive invocation.
	 */
	falcon_poly_split_fft(z0, z0 + hn, tmp, logn);
	falcon_ffSampling_fft(samp, samp_ctx, tmp, tmp + hn, tree0, z0, z0 + hn, logn - 1, tmp + n);
	falcon_poly_merge_fft(z0, tmp, tmp + hn, logn);
}

#endif

static void falcon_smallints_to_fpr(falcon_fpr* r, const int8_t* t, uint32_t logn)
{
	/*
	* Convert an integer polynomial (with small values) into the
	* representation with complex numbers.
	*/

	size_t n;
	size_t u;

	n = falcon_mkn(logn);

	for (u = 0; u < n; ++u)
	{
		r[u] = falcon_fpr_of(t[u]);
	}
}

static void falcon_ffSampling_fft_dyntree(falcon_samplerZ samp, void* samp_ctx, falcon_fpr* restrict t0, falcon_fpr* restrict t1,
	falcon_fpr* restrict g00, falcon_fpr* restrict g01, falcon_fpr* restrict g11, uint32_t orig_logn, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	* Perform Fast Fourier Sampling for target vector t. The Gram matrix
	* is provided (G = [[g00, g01], [adj(g01), g11]]). The sampled vector
	* is written over (t0,t1). The Gram matrix is modified as well. The
	* tmp[] buffer must have room for four polynomials.
	*/

	falcon_fpr* z0;
	falcon_fpr* z1;
	size_t hn;
	size_t n;

	/*
	 * Deepest level: the LDL tree leaf value is just g00 (the
	 * array has length only 1 at this point); we normalize it
	 * with regards to sigma, then use it for sampling.
	 */
	if (logn == 0)
	{
		falcon_fpr leaf;

		leaf = g00[0];
		leaf = falcon_fpr_mul(falcon_fpr_sqrt(leaf), falcon_fpr_inv_sigma[orig_logn]);
		t0[0] = falcon_fpr_of(samp(samp_ctx, t0[0], leaf));
		t1[0] = falcon_fpr_of(samp(samp_ctx, t1[0], leaf));

		return;
	}

	n = (size_t)1 << logn;
	hn = n >> 1;

	/*
	 * Decompose G into LDL. We only need d00 (identical to g00),
	 * d11, and l10; we do that in place.
	 */
	falcon_poly_LDL_fft(g00, g01, g11, logn);

	/*
	 * Split d00 and d11 and expand them into half-size quasi-cyclic
	 * Gram matrices. We also save l10 in tmp[].
	 */
	falcon_poly_split_fft(tmp, tmp + hn, g00, logn);
	qsc_memutils_copy(g00, tmp, n * sizeof(*tmp));
	falcon_poly_split_fft(tmp, tmp + hn, g11, logn);
	qsc_memutils_copy(g11, tmp, n * sizeof(*tmp));
	qsc_memutils_copy(tmp, g01, n * sizeof(*g01));
	qsc_memutils_copy(g01, g00, hn * sizeof(*g00));
	qsc_memutils_copy(g01 + hn, g11, hn * sizeof(*g00));

	/*
	 * The half-size Gram matrices for the recursive LDL tree
	 * building are now:
	 *   - left sub-tree: g00, g00+hn, g01
	 *   - right sub-tree: g11, g11+hn, g01+hn
	 * l10 is in tmp[].
	 */

	 /*
	  * We split t1 and use the first recursive call on the two
	  * halves, using the right sub-tree. The result is merged
	  * back into tmp + 2*n.
	  */
	z1 = tmp + n;
	falcon_poly_split_fft(z1, z1 + hn, t1, logn);
	falcon_ffSampling_fft_dyntree(samp, samp_ctx, z1, z1 + hn, g11, g11 + hn, g01 + hn, orig_logn, logn - 1, z1 + n);
	falcon_poly_merge_fft(tmp + (n << 1), z1, z1 + hn, logn);

	/*
	 * Compute tb0 = t0 + (t1 - z1) * l10.
	 * At that point, l10 is in tmp, t1 is unmodified, and z1 is
	 * in tmp + (n << 1). The buffer in z1 is free.
	 *
	 * In the end, z1 is written over t1, and tb0 is in t0.
	 */
	qsc_memutils_copy(z1, t1, n * sizeof(*t1));
	falcon_poly_sub(z1, tmp + (n << 1), logn);
	qsc_memutils_copy(t1, tmp + (n << 1), n * sizeof(*tmp));
	falcon_poly_mul_fft(tmp, z1, logn);
	falcon_poly_add(t0, tmp, logn);

	/*
	 * Second recursive invocation, on the split tb0 (currently in t0)
	 * and the left sub-tree.
	 */
	z0 = tmp;
	falcon_poly_split_fft(z0, z0 + hn, t0, logn);
	falcon_ffSampling_fft_dyntree(samp, samp_ctx, z0, z0 + hn, g00, g00 + hn, g01, orig_logn, logn - 1, z0 + n);
	falcon_poly_merge_fft(t0, z0, z0 + hn, logn);
}

static int32_t falcon_do_sign_dyn(falcon_samplerZ samp, void* samp_ctx, int16_t* s2, const int8_t* restrict f, const int8_t* restrict g,
	const int8_t* restrict F, const int8_t* restrict G, const uint16_t* hm, uint32_t logn, falcon_fpr* restrict tmp)
{
	/*
	* Compute a signature: the signature contains two vectors, s1 and s2.
	* The s1 vector is not returned. The squared norm of (s1,s2) is
	* computed, and if it is short enough, then s2 is returned into the
	* s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is
	* returned; the caller should then try again.
	*
	* tmp[] must have room for at least nine polynomials.
	*/

	falcon_fpr* t0;
	falcon_fpr* t1;
	falcon_fpr* tx;
	falcon_fpr* ty;
	falcon_fpr* b00;
	falcon_fpr* b01;
	falcon_fpr* b10;
	falcon_fpr* b11;
	falcon_fpr* g00;
	falcon_fpr* g01;
	falcon_fpr* g11;
	falcon_fpr ni;
	size_t n;
	size_t u;
	uint32_t sqn;
	uint32_t ng;
	int16_t* s1tmp;
	int16_t* s2tmp;

	n = falcon_mkn(logn);

	/*
	 * Lattice basis is B = [[g, -f], [G, -F]]. We convert it to FFT.
	 */
	b00 = tmp;
	b01 = b00 + n;
	b10 = b01 + n;
	b11 = b10 + n;
	falcon_smallints_to_fpr(b01, f, logn);
	falcon_smallints_to_fpr(b00, g, logn);
	falcon_smallints_to_fpr(b11, F, logn);
	falcon_smallints_to_fpr(b10, G, logn);
	falcon_FFT(b01, logn);
	falcon_FFT(b00, logn);
	falcon_FFT(b11, logn);
	falcon_FFT(b10, logn);
	falcon_poly_neg(b01, logn);
	falcon_poly_neg(b11, logn);

	/*
	 * Compute the Gram matrix G = B�B*. Formulas are:
	 *   g00 = b00*adj(b00) + b01*adj(b01)
	 *   g01 = b00*adj(b10) + b01*adj(b11)
	 *   g10 = b10*adj(b00) + b11*adj(b01)
	 *   g11 = b10*adj(b10) + b11*adj(b11)
	 *
	 * For historical reasons, this implementation uses
	 * g00, g01 and g11 (upper triangle). g10 is not kept
	 * since it is equal to adj(g01).
	 *
	 * We _replace_ the matrix B with the Gram matrix, but we
	 * must keep b01 and b11 for computing the target vector.
	 */
	t0 = b11 + n;
	t1 = t0 + n;

	qsc_memutils_copy(t0, b01, n * sizeof(*b01));
	falcon_poly_mulselfadj_fft(t0, logn);    // t0 <- b01*adj(b01)

	qsc_memutils_copy(t1, b00, n * sizeof(*b00));
	falcon_poly_muladj_fft(t1, b10, logn);   // t1 <- b00*adj(b10)
	falcon_poly_mulselfadj_fft(b00, logn);   // b00 <- b00*adj(b00)
	falcon_poly_add(b00, t0, logn);      // b00 <- g00
	qsc_memutils_copy(t0, b01, n * sizeof(*b01));
	falcon_poly_muladj_fft(b01, b11, logn);  // b01 <- b01*adj(b11)
	falcon_poly_add(b01, t1, logn);      // b01 <- g01

	falcon_poly_mulselfadj_fft(b10, logn);   // b10 <- b10*adj(b10)
	qsc_memutils_copy(t1, b11, n * sizeof(*b11));
	falcon_poly_mulselfadj_fft(t1, logn);    // t1 <- b11*adj(b11)
	falcon_poly_add(b10, t1, logn);      // b10 <- g11

	/*
	 * We rename variables to make things clearer. The three elements
	 * of the Gram matrix uses the first 3*n slots of tmp[], followed
	 * by b11 and b01 (in that order).
	 */
	g00 = b00;
	g01 = b01;
	g11 = b10;
	b01 = t0;
	t0 = b01 + n;
	t1 = t0 + n;

	/*
	 * Memory layout at that point:
	 *   g00 g01 g11 b11 b01 t0 t1
	 */

	 /*
	  * Set the target vector to [hm, 0] (hm is the hashed message).
	  */
	for (u = 0; u < n; ++u)
	{
		t0[u] = falcon_fpr_of(hm[u]);
		/* This is implicit */
	}

	/*
	 * Apply the lattice basis to obtain the real target
	 * vector (after normalization with regards to modulus).
	 */
	falcon_FFT(t0, logn);
	ni = falcon_fpr_inverse_of_q;
	qsc_memutils_copy(t1, t0, n * sizeof(*t0));
	falcon_poly_mul_fft(t1, b01, logn);
	falcon_poly_mulconst(t1, falcon_fpr_neg(ni), logn);
	falcon_poly_mul_fft(t0, b11, logn);
	falcon_poly_mulconst(t0, ni, logn);

	/*
	 * b01 and b11 can be discarded, so we move back (t0,t1).
	 * Memory layout is now: g00 g01 g11 t0 t1
	 */
	qsc_memutils_copy(b11, t0, n * 2 * sizeof(*t0));
	t0 = g11 + n;
	t1 = t0 + n;

	/*
	 * Apply sampling; result is written over (t0,t1).
	 */
	falcon_ffSampling_fft_dyntree(samp, samp_ctx, t0, t1, g00, g01, g11, logn, logn, t1 + n);

	/*
	 * We arrange the layout back to: b00 b01 b10 b11 t0 t1
	 * We did not conserve the matrix basis, so we must recompute
	 * it now.
	 */
	b00 = tmp;
	b01 = b00 + n;
	b10 = b01 + n;
	b11 = b10 + n;
	qsc_memutils_move(b11 + n, t0, n * 2 * sizeof(*t0));
	t0 = b11 + n;
	t1 = t0 + n;
	falcon_smallints_to_fpr(b01, f, logn);
	falcon_smallints_to_fpr(b00, g, logn);
	falcon_smallints_to_fpr(b11, F, logn);
	falcon_smallints_to_fpr(b10, G, logn);
	falcon_FFT(b01, logn);
	falcon_FFT(b00, logn);
	falcon_FFT(b11, logn);
	falcon_FFT(b10, logn);
	falcon_poly_neg(b01, logn);
	falcon_poly_neg(b11, logn);
	tx = t1 + n;
	ty = tx + n;

	/*
	 * Get the lattice point corresponding to that tiny vector.
	 */
	qsc_memutils_copy(tx, t0, n * sizeof(*t0));
	qsc_memutils_copy(ty, t1, n * sizeof(*t1));
	falcon_poly_mul_fft(tx, b00, logn);
	falcon_poly_mul_fft(ty, b10, logn);
	falcon_poly_add(tx, ty, logn);
	qsc_memutils_copy(ty, t0, n * sizeof(*t0));
	falcon_poly_mul_fft(ty, b01, logn);

	qsc_memutils_copy(t0, tx, n * sizeof(*tx));
	falcon_poly_mul_fft(t1, b11, logn);
	falcon_poly_add(t1, ty, logn);
	falcon_iFFT(t0, logn);
	falcon_iFFT(t1, logn);

	s1tmp = (int16_t*)tx;
	sqn = 0;
	ng = 0;

	for (u = 0; u < n; u++)
	{
		int32_t z;

		z = (int32_t)hm[u] - (int32_t)falcon_fpr_rint(t0[u]);
		sqn += (uint32_t)(z * z);
		ng |= sqn;
		s1tmp[u] = (int16_t)z;
	}

	sqn |= (uint32_t)-(int32_t)(ng >> 31);

	/*
	 * With "normal" degrees (e.g. 512 or 1024), it is very
	 * improbable that the computed vector is not short enough
	 * however, it may happen in practice for the very reduced
	 * versions (e.g. degree 16 or below). In that case, the caller
	 * will loop, and we must not write anything into s2[] because
	 * s2[] may overlap with the hashed message hm[] and we need
	 * hm[] for the next iteration.
	 */
	s2tmp = (int16_t *)tmp;

	for (u = 0; u < n; ++u)
	{
		s2tmp[u] = (int16_t)-falcon_fpr_rint(t1[u]);
	}

	if (falcon_is_short_half(sqn, s2tmp, logn) != 0)
	{
		qsc_memutils_copy(s2, s2tmp, n * sizeof(*s2));
		qsc_memutils_copy(tmp, s1tmp, n * sizeof(*s1tmp));
		return 1;
	}

	return 0;
}

static int32_t falcon_gaussian0_sampler(falcon_prng_state* p)
{
	/*
	* Sample an integer value along a half-gaussian distribution centered
	* on zero and standard deviation 1.8205, with a precision of 72 bits.
	*/
	static const uint32_t dist[] =
	{
		10745844U, 3068844U, 3741698U, 5559083U, 1580863U, 8248194U, 2260429U, 13669192U,
		2736639U, 708981U, 4421575U, 10046180U, 169348U, 7122675U, 4136815U, 30538U,
		13063405U, 7650655U, 4132U, 14505003U, 7826148U, 417U, 16768101U, 11363290U,
		31U, 8444042U, 8086568U, 1U, 12844466U, 265321U, 0U, 1232676U,
		13644283U, 0U, 38047U, 9111839U, 0U, 870U, 6138264U, 0U,
		14U, 12545723U, 0U, 0U, 3104126U, 0U, 0U, 28824U,
		0U, 0U, 198U, 0U, 0U, 1U
	};

	uint32_t v0;
	uint32_t v1;
	uint32_t v2;
	uint32_t hi;
	uint64_t lo;
	size_t u;
	int32_t z;

	/*
	 * Get a random 72-bit value, into three 24-bit limbs v0..v2.
	 */
	lo = falcon_prng_get_u64(p);
	hi = falcon_prng_get_u8(p);
	v0 = (uint32_t)lo & 0xFFFFFF;
	v1 = (uint32_t)(lo >> 24) & 0xFFFFFF;
	v2 = (uint32_t)(lo >> 48) | (hi << 16);

	/*
	 * Sampled value is z, such that v0..v2 is lower than the first
	 * z elements of the table.
	 */
	z = 0;

	for (u = 0; u < (sizeof(dist) / sizeof(dist[0])); u += 3)
	{
		uint32_t w0;
		uint32_t w1;
		uint32_t w2;
		uint32_t cc;

		w0 = dist[u + 2];
		w1 = dist[u + 1];
		w2 = dist[u];
		cc = (v0 - w0) >> 31;
		cc = (v1 - w1 - cc) >> 31;
		cc = (v2 - w2 - cc) >> 31;
		z += (int32_t)cc;
	}

	return z;
}

static int32_t falcon_BerExp(falcon_prng_state* p, falcon_fpr x, falcon_fpr ccs)
{
	/*
	* Sample a bit with probability exp(-x) for some x >= 0.
	*/

	falcon_fpr r;
	uint64_t z;
	int32_t i;
	int32_t s;
	uint32_t sw;
	uint32_t w;

	/*
	 * Reduce x modulo log(2): x = s*log(2) + r, with s an integer,
	 * and 0 <= r < log(2). Since x >= 0, we can use falcon_fpr_trunc().
	 */
	s = (int32_t)falcon_fpr_trunc(falcon_fpr_mul(x, falcon_fpr_inv_log2));
	r = falcon_fpr_sub(x, falcon_fpr_mul(falcon_fpr_of(s), falcon_fpr_log2));

	/*
	 * It may happen (quite rarely) that s >= 64; if sigma = 1.2
	 * (the minimum value for sigma), r = 0 and b = 1, then we get
	 * s >= 64 if the half-Gaussian produced a z >= 13, which happens
	 * with probability about 0.000000000230383991, which is
	 * approximatively equal to 2^(-32). In any case, if s >= 64,
	 * then falcon_BerExp will be non-zero with probability less than
	 * 2^(-64), so we can simply saturate s at 63.
	 */
	sw = (uint32_t)s;
	sw ^= (sw ^ 63) & (uint32_t)-(int32_t)((63 - sw) >> 31);
	s = (int32_t)sw;

	/*
	 * Compute exp(-r); we know that 0 <= r < log(2) at this point, so
	 * we can use falcon_fpr_expm_p63(), which yields a result scaled to 2^63.
	 * We scale it up to 2^64, then right-shift it by s bits because
	 * we really want exp(-x) = 2^(-s)*exp(-r).
	 *
	 * The "-1" operation makes sure that the value fits on 64 bits
	 * (i.e. if r = 0, we may get 2^64, and we prefer 2^64-1 in that
	 * case). The bias is negligible since falcon_fpr_expm_p63() only computes
	 * with 51 bits of precision or so.
	 */
	z = ((falcon_fpr_expm_p63(r, ccs) << 1) - 1) >> s;

	/*
	 * Sample a bit with probability exp(-x). Since x = s*log(2) + r,
	 * exp(-x) = 2^-s * exp(-r), we compare lazily exp(-x) with the
	 * PRNG output to limit its consumption, the sign of the difference
	 * yields the expected result.
	 */
	i = 64;

	do
	{
		i -= 8;
		w = falcon_prng_get_u8(p) - ((uint32_t)(z >> i) & 0xFF);
	} while (w == 0 && i > 0);

	return (int32_t)(w >> 31);
}

static int32_t falcon_sampler(void* ctx, falcon_fpr mu, falcon_fpr isigma)
{
	/*
	* The sampler produces a random integer that follows a discrete Gaussian
	* distribution, centered on mu, and with standard deviation sigma. The
	* provided parameter isigma is equal to 1/sigma.
	*
	* The value of sigma MUST lie between 1 and 2 (i.e. isigma lies between
	* 0.5 and 1); in Falcon, sigma should always be between 1.2 and 1.9.
	*/

	falcon_fpr r;
	falcon_fpr dss;
	falcon_fpr ccs;
	falcon_sampler_context *spc;
	int32_t s;

	spc = ctx;

	/*
	 * Center is mu. We compute mu = s + r where s is an integer
	 * and 0 <= r < 1.
	 */
	s = (int32_t)falcon_fpr_floor(mu);
	r = falcon_fpr_sub(mu, falcon_fpr_of(s));

	/*
	 * dss = 1/(2*sigma^2) = 0.5*(isigma^2).
	 */
	dss = falcon_fpr_half(falcon_fpr_sqr(isigma));

	/*
	 * ccs = sigma_min / sigma = sigma_min * isigma.
	 */
	ccs = falcon_fpr_mul(isigma, spc->sigma_min);

	/*
	 * We now need to sample on center r.
	 */
	while (true)
	{
		int32_t z0;
		int32_t z;
		int32_t b;
		falcon_fpr x;

		/*
		 * Sample z for a Gaussian distribution. Then get a
		 * random bit b to turn the sampling into a bimodal
		 * distribution: if b = 1, we use z+1, otherwise we
		 * use -z. We thus have two situations:
		 *
		 *  - b = 1: z >= 1 and sampled against a Gaussian
		 *    centered on 1.
		 *  - b = 0: z <= 0 and sampled against a Gaussian
		 *    centered on 0.
		 */
		z0 = falcon_gaussian0_sampler(&spc->p);
		b = (int32_t)falcon_prng_get_u8(&spc->p) & 1;
		z = b + ((b << 1) - 1) * z0;

		/*
		 * Rejection sampling. We want a Gaussian centered on r
		 * but we sampled against a Gaussian centered on b (0 or
		 * 1). But we know that z is always in the range where
		 * our sampling distribution is greater than the Gaussian
		 * distribution, so rejection works.
		 *
		 * We got z with distribution:
		 *    G(z) = exp(-((z-b)^2)/(2*sigma0^2))
		 * We target distribution:
		 *    S(z) = exp(-((z-r)^2)/(2*sigma^2))
		 * Rejection sampling works by keeping the value z with
		 * probability S(z)/G(z), and starting again otherwise.
		 * This requires S(z) <= G(z), which is the case here.
		 * Thus, we simply need to keep our z with probability:
		 *    P = exp(-x)
		 * where:
		 *    x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
		 *
		 * Here, we scale up the Bernouilli distribution, which
		 * makes rejection more probable, but makes rejection
		 * rate sufficiently decorrelated from the Gaussian
		 * center and standard deviation that the whole sampler
		 * can be said to be constant-time.
		 */
		x = falcon_fpr_mul(falcon_fpr_sqr(falcon_fpr_sub(falcon_fpr_of(z), r)), dss);
		x = falcon_fpr_sub(x, falcon_fpr_mul(falcon_fpr_of(z0 * z0), falcon_fpr_inv_2sqrsigma0));

		if (falcon_BerExp(&spc->p, x, ccs) != 0)
		{
			/*
			 * Rejection sampling was centered on r, but the
			 * actual center is mu = s + r.
			 */
			return s + z;
		}
	}
}

static void falcon_sign_dyn(int16_t* sig, qsc_keccak_state* kctx, const int8_t* restrict f, const int8_t* restrict g,
	const int8_t* restrict F, const int8_t* restrict G, const uint16_t* hm, uint32_t logn, uint8_t* tmp)
{
	falcon_fpr* ftmp;

	ftmp = (falcon_fpr*)tmp;

	for (;;)
	{
		/*
		 * Signature produces short vectors s1 and s2. The
		 * signature is acceptable only if the aggregate vector
		 * s1,s2 is short; we must use the same bound as the
		 * verifier.
		 *
		 * If the signature is acceptable, then we return only s2
		 * (the verifier recomputes s1 from s2, the hashed message,
		 * and the public key).
		 */
		falcon_sampler_context spc = { 0 };
		falcon_samplerZ samp;
		void *samp_ctx;

		/*
		 * Normal sampling. We use a fast PRNG seeded from our
		 * SHAKE context ('rng').
		 */
		spc.sigma_min = falcon_fpr_sigma_min[logn];
		falcon_prng_init(&spc.p, kctx);
		samp = falcon_sampler;
		samp_ctx = &spc;

		/*
		 * Do the actual signature.
		 */
		if (falcon_do_sign_dyn(samp, samp_ctx, sig, f, g, F, G, hm, logn, ftmp) != 0)
		{
			break;
		}
	}
}

#if defined(QSC_FALCON_S3SHAKE256F512)

int32_t qsc_falcon_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t b[FALCON_KEYGEN_TEMP_9];
	int8_t f[512];
	int8_t g[512];
	int8_t F[512];
	uint16_t h[512];
	uint8_t seed[48];
	qsc_keccak_state kctx;
	size_t u;
	size_t v;

	/*
	 * Generate key pair.
	 */
	rng_generate(seed, sizeof(seed));
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, sizeof(seed));
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_keygen(&kctx, f, g, F, NULL, h, 9, b);

	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 9;
	u = 1;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, f, 9, falcon_max_fg_bits[9]);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, g, 9, falcon_max_fg_bits[9]);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, F, 9, falcon_max_FG_bits[9]);

	if (v == 0)
	{
		return -1;
	}

	u += v;

	if (u != FALCON_CRYPTO_SECRETKEYBYTES)
	{
		return -1;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + 9;
	v = falcon_modq_encode(pk + 1, FALCON_CRYPTO_PUBLICKEY_BYTES - 1, h, 9);

	if (v != FALCON_CRYPTO_PUBLICKEY_BYTES - 1)
	{
		return -1;
	}

	return 0;
}

int32_t qsc_falcon_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t))
{
	int16_t sig[512];
	uint8_t b[72 * 512];
	int8_t f[512];
	int8_t g[512];
	int8_t F[512];
	int8_t G[512];
	uint8_t seed[48];
	uint8_t nonce[FALCON_NONCE_SIZE];
	uint8_t esig[FALCON_CRYPTO_SIGNATURE_BYTES - 2 - sizeof(nonce)];
	qsc_keccak_state kctx;
	size_t u;
	size_t v;
	size_t siglen;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 9)
	{
		return -1;
	}

	u = 1;
	v = falcon_trim_i8_decode(f, 9, falcon_max_fg_bits[9], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_decode(g, 9, falcon_max_fg_bits[9], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_decode(F, 9, falcon_max_FG_bits[9], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;

	if (u != FALCON_CRYPTO_SECRETKEYBYTES)
	{
		return -1;
	}

	if (!falcon_complete_private(G, f, g, F, 9, b))
	{
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	rng_generate(nonce, sizeof(nonce));

	/*
	 * Hash message nonce + message into a vector.
	 */
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, nonce, sizeof(nonce));
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_hash_to_point_vartime(&kctx, (uint16_t*)sig, 9);

	/*
	 * Initialize a RNG.
	 */
	rng_generate(seed, sizeof(seed));
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, sizeof(seed));
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);


	/*
	 * Compute the signature.
	 */
	falcon_sign_dyn(sig, &kctx, f, g, F, G, (uint16_t*)sig, 9, b);


	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + 9;
	siglen = falcon_comp_encode(esig + 1, (sizeof(esig)) - 1, sig, 9);

	if (siglen == 0)
	{
		return -1;
	}

	siglen++;
	qsc_memutils_move(sm + 2 + sizeof(nonce), m, mlen);
	sm[0] = (uint8_t)(siglen >> 8);
	sm[1] = (uint8_t)siglen;
	qsc_memutils_copy(sm + 2, nonce, sizeof(nonce));
	qsc_memutils_copy(sm + 2 + sizeof(nonce) + mlen, esig, siglen);
	*smlen = 2 + sizeof(nonce) + mlen + siglen;

	return 0;
}

bool qsc_falcon_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
	uint16_t h[512];
	uint16_t hm[512];
	int16_t sig[512];
	uint8_t b[2 * 512];
	const uint8_t* esig;
	qsc_keccak_state kctx;
	size_t msglen;
	size_t siglen;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9)
	{
		return false;
	}

	if (falcon_modq_decode(h, 9, pk + 1, FALCON_CRYPTO_PUBLICKEY_BYTES - 1) != FALCON_CRYPTO_PUBLICKEY_BYTES - 1)
	{
		return false;
	}

	falcon_to_ntt_monty(h, 9);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + FALCON_NONCE_SIZE)
	{
		return false;
	}

	siglen = ((size_t)sm[0] << 8) | (size_t)sm[1];

	if (siglen > (smlen - 2 - FALCON_NONCE_SIZE))
	{
		return false;
	}

	msglen = smlen - 2 - FALCON_NONCE_SIZE - siglen;

	/*
	 * Decode signature.
	 */
	esig = sm + 2 + FALCON_NONCE_SIZE + msglen;

	if (siglen < 1 || esig[0] != 0x20 + 9)
	{
		return false;
	}

	if (falcon_comp_decode(sig, 9, esig + 1, siglen - 1) != siglen - 1)
	{
		return false;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sm + 2, FALCON_NONCE_SIZE + msglen);
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_hash_to_point_vartime(&kctx, hm, 9);

	/*
	 * Verify signature.
	 */
	if (!falcon_verify_raw(hm, sig, h, 9, b))
	{
		return false;
	}

	/*
	 * Return plaintext.
	 */
	qsc_memutils_move(m, sm + 2 + FALCON_NONCE_SIZE, msglen);
	*mlen = msglen;

	return true;
}


#elif defined(QSC_FALCON_S5SHAKE256F1024)

int32_t qsc_falcon_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	uint16_t h[1024];
	uint8_t b[FALCON_KEYGEN_TEMP_10];
	int8_t f[1024];
	int8_t g[1024];
	int8_t F[1024];
	uint8_t seed[48];
	qsc_keccak_state kctx;
	size_t u;
	size_t v;

	/*
	 * Generate key pair.
	 */
	rng_generate(seed, sizeof(seed));
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, sizeof(seed));
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_keygen(&kctx, f, g, F, NULL, h, 10, b);


	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 10;
	u = 1;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, f, 10, falcon_max_fg_bits[10]);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, g, 10, falcon_max_fg_bits[10]);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_encode(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u, F, 10, falcon_max_FG_bits[10]);

	if (v == 0)
	{
		return -1;
	}

	u += v;

	if (u != FALCON_CRYPTO_SECRETKEYBYTES)
	{
		return -1;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + 10;
	v = falcon_modq_encode(pk + 1, FALCON_CRYPTO_PUBLICKEY_BYTES - 1, h, 10);

	if (v != FALCON_CRYPTO_PUBLICKEY_BYTES - 1)
	{
		return -1;
	}

	return 0;
}

int32_t qsc_falcon_ref_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	int16_t sig[1024] = { 0 };
	uint8_t b[72 * 1024];
	int8_t f[1024];
	int8_t g[1024];
	int8_t F[1024];
	int8_t G[1024];
	uint8_t seed[48];
	uint8_t nonce[FALCON_NONCE_SIZE];
	uint8_t esig[FALCON_CRYPTO_SIGNATURE_BYTES - 2 - sizeof(nonce)] = { 0 };
	qsc_keccak_state kctx;
	size_t u;
	size_t v;
	size_t siglen;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 10)
	{
		return -1;
	}

	u = 1;
	v = falcon_trim_i8_decode(f, 10, falcon_max_fg_bits[10], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_decode(g, 10, falcon_max_fg_bits[10], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;
	v = falcon_trim_i8_decode(F, 10, falcon_max_FG_bits[10], sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);

	if (v == 0)
	{
		return -1;
	}

	u += v;

	if (u != FALCON_CRYPTO_SECRETKEYBYTES)
	{
		return -1;
	}

	if (falcon_complete_private(G, f, g, F, 10, b) == 0)
	{
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	rng_generate(nonce, sizeof(nonce));

	/*
	 * Hash message nonce + message into a vector.
	 */
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, nonce, sizeof(nonce));
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, m, mlen);
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_hash_to_point_vartime(&kctx, (uint16_t*)sig, 10);

	/*
	 * Initialize a RNG.
	 */
	rng_generate(seed, sizeof(seed));
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, seed, sizeof(seed));
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);

	/*
	 * Compute the signature.
	 */
	falcon_sign_dyn(sig, &kctx, f, g, F, G, (uint16_t*)sig, 10, b);

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + 10;
	siglen = falcon_comp_encode(esig + 1, sizeof(esig) - 1, sig, 10);

	if (siglen == 0)
	{
		return -1;
	}

	siglen++;
	qsc_memutils_move(sm + 2 + sizeof(nonce), m, mlen);
	sm[0] = (uint8_t)(siglen >> 8);
	sm[1] = (uint8_t)siglen;
	qsc_memutils_copy(sm + 2, nonce, sizeof(nonce));
	qsc_memutils_copy(sm + 2 + sizeof(nonce) + mlen, esig, siglen);
	*smlen = 2 + sizeof(nonce) + mlen + siglen;

	return 0;
}

bool qsc_falcon_ref_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* pk)
{
	uint16_t h[1024];
	uint16_t hm[1024];
	int16_t sig[1024];
	uint8_t b[2 * 1024];
	const uint8_t* esig;
	qsc_keccak_state kctx;
	size_t siglen;
	size_t msglen;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 10)
	{
		return false;
	}

	if (falcon_modq_decode(h, 10, pk + 1, FALCON_CRYPTO_PUBLICKEY_BYTES - 1) != FALCON_CRYPTO_PUBLICKEY_BYTES - 1)
	{
		return false;
	}

	falcon_to_ntt_monty(h, 10);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + FALCON_NONCE_SIZE)
	{
		return false;
	}

	siglen = ((size_t)sm[0] << 8) | (size_t)sm[1];

	if (siglen > (smlen - 2 - FALCON_NONCE_SIZE))
	{
		return false;
	}

	msglen = smlen - 2 - FALCON_NONCE_SIZE - siglen;

	/*
	 * Decode signature.
	 */
	esig = sm + 2 + FALCON_NONCE_SIZE + msglen;

	if (siglen < 1 || esig[0] != 0x20 + 10)
	{
		return false;
	}

	if (falcon_comp_decode(sig, 10, esig + 1, siglen - 1) != siglen - 1)
	{
		return false;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	qsc_keccak_initialize_state(&kctx);
	qsc_keccak_incremental_absorb(&kctx, QSC_KECCAK_256_RATE, sm + 2, FALCON_NONCE_SIZE + msglen);
	qsc_keccak_incremental_finalize(&kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
	falcon_hash_to_point_vartime(&kctx, hm, 10);

	/*
	 * Verify signature.
	 */
	if (falcon_verify_raw(hm, sig, h, 10, b) == 0)
	{
		return false;
	}

	/*
	 * Return plaintext.
	 */
	qsc_memutils_move(m, sm + 2 + FALCON_NONCE_SIZE, msglen);
	*mlen = msglen;

	return true;
}

#endif
