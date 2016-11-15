/*
 * Copyright (c) 2013-2016 ARM Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * -----------------------------------------------------------------------------
 *
 * Project:     CMSIS-RTOS RTX
 * Title:       Cortex-M Core definitions
 *
 * -----------------------------------------------------------------------------
 */

#ifndef CORE_CM_H_
#define CORE_CM_H_

#include "RTE_Components.h"
#include CMSIS_device_header

#pragma diag_suppress=Pe550

#if (__CORE__ == __ARM6M__  )
#define __ARM_ARCH_6M__         1U
#elif (__CORE__ == __ARM7M__  )
#define __ARM_ARCH_7M__         1U
#elif (__CORE__ == __ARM7EM__  )
#define __ARM_ARCH_7EM__        1U
#endif

#if (defined (__CC_ARM) && !defined(__ARM_ARCH_7M__) && !defined(__ARM_ARCH_7EM__))
#define __ARM_ARCH_6M__         1U
#endif

#ifndef __ARM_ARCH_6M__
#define __ARM_ARCH_6M__         0U
#endif
#ifndef __ARM_ARCH_7M__
#define __ARM_ARCH_7M__         0U
#endif
#ifndef __ARM_ARCH_7EM__
#define __ARM_ARCH_7EM__        0U
#endif
#ifndef __ARM_ARCH_8M_BASE__
#define __ARM_ARCH_8M_BASE__    0U
#endif
#ifndef __ARM_ARCH_8M_MAIN__
#define __ARM_ARCH_8M_MAIN__    0U
#endif

#if   ((__ARM_ARCH_6M__      + \
        __ARM_ARCH_7M__      + \
        __ARM_ARCH_7EM__     + \
        __ARM_ARCH_8M_BASE__ + \
        __ARM_ARCH_8M_MAIN__) != 1U)
#error "Unknown ARM Architecture!"
#endif

#ifdef RTE_CMSIS_RTOS2_RTX5_ARMV8M_NS
#define __DOMAIN_NS             1U
#endif

#ifndef __DOMAIN_NS
#define __DOMAIN_NS             0U
#elif ((__DOMAIN_NS          == 1U) && \
      ((__ARM_ARCH_6M__      == 1U) || \
       (__ARM_ARCH_7M__      == 1U) || \
       (__ARM_ARCH_7EM__     == 1U)))
#error "Non-secure domain requires ARMv8-M Architecture!"
#endif

#ifndef __EXCLUSIVE_ACCESS
#if   ((__ARM_ARCH_7M__      == 1U) || \
       (__ARM_ARCH_7EM__     == 1U) || \
       (__ARM_ARCH_8M_BASE__ == 1U) || \
       (__ARM_ARCH_8M_MAIN__ == 1U))
#define __EXCLUSIVE_ACCESS      1U
#else
#define __EXCLUSIVE_ACCESS      0U
#endif
#endif


#define IS_PRIVILEGED()         ((__get_CONTROL() & 1U) == 0U)

#define IS_IRQ_MODE()            (__get_IPSR() != 0U)

#if   ((__ARM_ARCH_7M__      == 1U) || \
       (__ARM_ARCH_7EM__     == 1U) || \
       (__ARM_ARCH_8M_MAIN__ == 1U))
#define IS_IRQ_MASKED()         ((__get_PRIMASK() != 0U) || (__get_BASEPRI() != 0U))
#else
#define IS_IRQ_MASKED()          (__get_PRIMASK() != 0U)
#endif

#define XPSR_INITIAL_VALUE      0x01000000U

#if    (__DOMAIN_NS == 1U)
#define STACK_FRAME_INIT        0xBCU
#else
#define STACK_FRAME_INIT        0xFDU
#endif

#define IS_EXTENDED_STACK_FRAME(n) (((n) & 0x10U) == 0U)

#ifndef   __INLINE_FORCED
  #define __INLINE_FORCED           _Pragma( STRINGIFY(inline=forced) )
#endif

#ifdef    __STATIC_INLINE
  #undef  __STATIC_INLINE
  #define __STATIC_INLINE           static
#endif

//  ==== Service Calls definitions ====

#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
// CLang above 6.0 =============================================================

#define SVC_ArgN(n) \
register uint32_t __r##n __ASM("r"#n)

#define SVC_ArgR(n,a) \
register uint32_t __r##n __ASM("r"#n) = (uint32_t)a

#define SVC_ArgF(f) \
register uint32_t __rf   __ASM(SVC_RegF) = (uint32_t)f

#else
// IAR C Compiler ==============================================================


#if ( 0 )
#define SVC_ArgN(n)               \
register uint32_t __r##n;         \
  __ASM("MOV %0, %1"              \
  : "=r"(__r##n)                  \
  : "r" (__r##n) )
#else
#define SVC_ArgN(n)               \
register uint32_t __r##n
#endif

#define SVC_ArgR(n,a)             \
register uint32_t __r##n;         \
  __ASM("MOV %0, %1"              \
  : "=r"(__r##n)                  \
  : "r" (a) )

#if   ((__ARM_ARCH_7M__      == 1U) || \
       (__ARM_ARCH_7EM__     == 1U) || \
       (__ARM_ARCH_8M_MAIN__ == 1U))

#define SVC_ArgF(f)               \
register uint32_t __rf;           \
  __ASM("MOV %0, %0"              \
  : "=r"(__rf) );                 \
  __ASM("MOV r12, %0"             \
  : : "r" (f) )

#elif ((__ARM_ARCH_6M__      == 1U) || \
       (__ARM_ARCH_8M_BASE__ == 1U))

#define SVC_ArgF(f)               \
register uint32_t __rf;           \
  __ASM("MOV %0, %0"              \
  : "=r"(__rf) );                 \
  __ASM("MOV r7, %0"              \
  : : "r" (f) )

#endif

#endif

#define SVC_In0 "r"(__rf)
#define SVC_In1 "r"(__rf),"r"(__r0)
#define SVC_In2 "r"(__rf),"r"(__r0),"r"(__r1)
#define SVC_In3 "r"(__rf),"r"(__r0),"r"(__r1),"r"(__r2)
#define SVC_In4 "r"(__rf),"r"(__r0),"r"(__r1),"r"(__r2),"r"(__r3)

#define SVC_Out0
#define SVC_Out1 "=r"(__r0)

#define SVC_CL0 "r0","r1","r2","r3","lr","cc"
#define SVC_CL1      "r1","r2","r3","lr","cc"
#define SVC_CL2           "r2","r3","lr","cc"
#define SVC_CL3                "r3","lr","cc"
#define SVC_CL4                     "lr","cc"

#define SVC_Call0(in, out, cl)                                                 \
  __ASM volatile ("svc 0" : out : in : cl)

#define SVC0_0N(f,t)                                                           \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (void) {                                            \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In0, SVC_Out0, SVC_CL0);                                       \
}

#define SVC0_0(f,t)                                                            \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (void) {                                            \
  SVC_ArgN(0);                                                                 \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In0, SVC_Out1, SVC_CL1);                                       \
  return (t) __r0;                                                             \
}

#define SVC0_1N(f,t,t1)                                                        \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (t1 a1) {                                           \
  SVC_ArgR(0,a1);                                                              \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In1, SVC_Out0, SVC_CL1);                                       \
}

#define SVC0_1(f,t,t1)                                                         \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (t1 a1) {                                           \
  SVC_ArgR(0,a1);                                                              \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In1, SVC_Out1, SVC_CL1);                                       \
  return (t) __r0;                                                             \
}

#define SVC0_2(f,t,t1,t2)                                                      \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (t1 a1, t2 a2) {                                    \
  SVC_ArgR(0,a1);                                                              \
  SVC_ArgR(1,a2);                                                              \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In2, SVC_Out1, SVC_CL2);                                       \
  return (t) __r0;                                                             \
}

#define SVC0_3(f,t,t1,t2,t3)                                                   \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (t1 a1, t2 a2, t3 a3) {                             \
  SVC_ArgR(0,a1);                                                              \
  SVC_ArgR(1,a2);                                                              \
  SVC_ArgR(2,a3);                                                              \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In3, SVC_Out1, SVC_CL3);                                       \
  return (t) __r0;                                                             \
}

#define SVC0_4(f,t,t1,t2,t3,t4)                                                \
__INLINE_FORCED                                                                \
__STATIC_INLINE t __svc##f (t1 a1, t2 a2, t3 a3, t4 a4) {                      \
  SVC_ArgR(0,a1);                                                              \
  SVC_ArgR(1,a2);                                                              \
  SVC_ArgR(2,a3);                                                              \
  SVC_ArgR(3,a4);                                                              \
  SVC_ArgF(os_svc##f);                                                         \
  SVC_Call0(SVC_In4, SVC_Out1, SVC_CL4);                                       \
  return (t) __r0;                                                             \
}


//  ==== Core Peripherals functions ====

extern uint32_t SystemCoreClock;        // System Clock Frequency (Core Clock)


/// Initialize SVC and PendSV System Service Calls
__STATIC_INLINE void os_SVC_Initialize (void) {
#if   (__ARM_ARCH_8M_MAIN__ == 1U)
  uint32_t p, n;

  SCB->SHPR[10] = 0xFFU;
  n = 32U - (uint32_t)__CLZ(~(SCB->SHPR[10] | 0xFFFFFF00U));
  p = NVIC_GetPriorityGrouping();
  if (p >= n) {
    n = p + 1U;
  }
  SCB->SHPR[7] = (uint8_t)(0xFEU << n);
#elif (__ARM_ARCH_8M_BASE__ == 1U)
  SCB->SHPR[1] |= 0x00FF0000U;
  SCB->SHPR[0] |= (SCB->SHPR[1] << (8+1)) & 0xFC000000U;
#elif ((__ARM_ARCH_7M__ == 1U) || (__ARM_ARCH_7EM__ == 1U))
  uint32_t p, n;

  SCB->SHP[10] = 0xFFU;
  n = 32U - (uint32_t)__CLZ(~(SCB->SHP[10] | 0xFFFFFF00U));
  p = NVIC_GetPriorityGrouping();
  if (p >= n) {
    n = p + 1U;
  }
  SCB->SHP[7] = (uint8_t)(0xFEU << n);
#elif (__ARM_ARCH_6M__ == 1U)
  SCB->SHP[1] |= 0x00FF0000U;
  SCB->SHP[0] |= (SCB->SHP[1] << (8+1)) & 0xFC000000U;
#endif
}

/// Setup SysTick Timer
/// \param[in] period  Timer Load value
__STATIC_INLINE void os_SysTick_Setup (uint32_t period) {
  SysTick->LOAD = period - 1U;
  SysTick->VAL  = 0U;
#if   (__ARM_ARCH_8M_MAIN__ == 1U)
  SCB->SHPR[11] = 0xFFU;
#elif (__ARM_ARCH_8M_BASE__ == 1U)
  SCB->SHPR[1] |= 0xFF000000U;
#elif ((__ARM_ARCH_7M__ == 1U) || (__ARM_ARCH_7EM__ == 1U))
  SCB->SHP[11]  = 0xFFU;
#elif (__ARM_ARCH_6M__ == 1U)
  SCB->SHP[1]  |= 0xFF000000U;
#endif
}

/// Get SysTick Period
/// \return    SysTick Period
__STATIC_INLINE uint32_t os_SysTick_GetPeriod (void) {
  return (SysTick->LOAD + 1U);
}

/// Get SysTick Value
/// \return    SysTick Value
__STATIC_INLINE uint32_t os_SysTick_GetVal (void) {
  uint32_t Load, Val;
  Load = SysTick->LOAD;
  Val = SysTick->VAL;
  return ( Load - Val );
}

/// Get SysTick Overflow (Auto Clear)
/// \return    SysTick Overflow flag
__STATIC_INLINE uint32_t os_SysTick_GetOvf (void) {
  return ((SysTick->CTRL >> 16) & 1U);
}

/// Enable SysTick Timer
__STATIC_INLINE void os_SysTick_Enable (void) {
  SysTick->CTRL = SysTick_CTRL_ENABLE_Msk     |
                  SysTick_CTRL_TICKINT_Msk    |
                  SysTick_CTRL_CLKSOURCE_Msk;
}

/// Disable SysTick Timer
__STATIC_INLINE void os_SysTick_Disable (void) {
  SysTick->CTRL = 0U;
}

/// Setup External Tick Timer Interrupt
/// \param[in] irqn  Interrupt number
__STATIC_INLINE void os_ExtTick_SetupIRQ (int32_t irqn) {
#if    (__ARM_ARCH_8M_MAIN__ == 1U)
  NVIC->IPR[irqn] = 0xFFU;
#elif  (__ARM_ARCH_8M_BASE__ == 1U)
  NVIC->IPR[irqn >> 2] = (NVIC->IPR[irqn >> 2]  & ~(0xFFU << ((irqn & 3) << 3))) |
                                                   (0xFFU << ((irqn & 3) << 3));
#elif ((__ARM_ARCH_7M__      == 1U) || \
       (__ARM_ARCH_7EM__     == 1U))
  NVIC->IP[irqn] = 0xFFU;
#elif  (__ARM_ARCH_6M__      == 1U)
  NVIC->IP[irqn >> 2] = (NVIC->IP[irqn >> 2]  & ~(0xFFU << ((irqn & 3) << 3))) |
                                                 (0xFFU << ((irqn & 3) << 3));
#endif
}

/// Enable External Tick Timer Interrupt
/// \param[in] irqn  Interrupt number
__STATIC_INLINE void os_ExtTick_EnableIRQ (int32_t irqn) {
  NVIC->ISER[irqn >> 5] = 1U << (irqn & 0x1F);
}

/// Disable External Tick Timer Interrupt
/// \param[in] irqn  Interrupt number
__STATIC_INLINE void os_ExtTick_DisableIRQ (int32_t irqn) {
  NVIC->ICER[irqn >> 5] = 1U << (irqn & 0x1F);
}

/// Get Pending SV (Service Call) and ST (SysTick) Flags
/// \return    Pending SV&ST Flags
__STATIC_INLINE uint8_t os_GetPendSV_ST (void) {
  return ((uint8_t)((SCB->ICSR & (SCB_ICSR_PENDSVSET_Msk | SCB_ICSR_PENDSTSET_Msk)) >> 24));
}

/// Get Pending SV (Service Call) Flag
/// \return    Pending SV Flag
__STATIC_INLINE uint8_t os_GetPendSV (void) {
  return ((uint8_t)((SCB->ICSR & (SCB_ICSR_PENDSVSET_Msk)) >> 24));
}

/// Clear Pending SV (Service Call) and ST (SysTick) Flags
__STATIC_INLINE void os_ClrPendSV_ST (void) {
  SCB->ICSR = SCB_ICSR_PENDSVCLR_Msk | SCB_ICSR_PENDSTCLR_Msk;
}

/// Clear Pending SV (Service Call) Flag
__STATIC_INLINE void os_ClrPendSV (void) {
  SCB->ICSR = SCB_ICSR_PENDSVCLR_Msk;
}

/// Set Pending SV (Service Call) Flag
__STATIC_INLINE void os_SetPendSV (void) {
  SCB->ICSR = SCB_ICSR_PENDSVSET_Msk;
}

/// Set Pending Flags
/// \param[in] flags  Flags to set
__STATIC_INLINE void os_SetPendFlags (uint8_t flags) {
  SCB->ICSR = ((uint32_t)flags << 24);
}


//  ==== Exclusive Access Operation ====

#if (__EXCLUSIVE_ACCESS == 1U)

/// Exclusive Access Operation: Write (8-bit)
/// \param[in]  mem             Memory address
/// \param[in]  val             Value to write
/// \return                     Previous value
__STATIC_INLINE uint8_t os_exc_wr8 (uint8_t *mem, uint8_t val) {
  register uint32_t res;
  register uint8_t  ret;

  __ASM volatile (
  "Label1:\n"
    "ldrexb %[ret],[%[mem]]\n"
    "strexb %[res],%[val],[%[mem]]\n"
    "cbz    %[res],Label2\n"
    "b       Label1\n"
  "Label2:\n"
  : [ret] "=&l" (ret),
    [res] "=&l" (res)
  : [mem] "l"   (mem),
    [val] "l"   (val)
  : "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Set bits (32-bit)
/// \param[in]  mem             Memory address
/// \param[in]  bits            Bit mask
/// \return                     New value
__STATIC_INLINE uint32_t os_exc_set32 (uint32_t *mem, uint32_t bits) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[val],[%[mem]]\n"
#if (__ARM_ARCH_8M_BASE__ == 1U)
    "mov   %[ret],%[val]\n"
    "orrs  %[ret],%[bits]\n"
#else
    "orr   %[ret],%[val],%[bits]\n"
#endif
    "strex %[res],%[ret],[%[mem]]\n"
    "cbz   %[res],Label2\n"
    "b     Label1\n"
  "Label2:\n"
  : [ret]  "=&l" (ret),
    [val]  "=&l" (val),
    [res]  "=&l" (res)
  : [mem]  "l"   (mem),
    [bits] "l"   (bits)
#if (__ARM_ARCH_8M_BASE__ == 1U)
  : "memory", "cc"
#else
  : "memory"
#endif
  );

  return ret;
}

/// Exclusive Access Operation: Clear bits (32-bit)
/// \param[in]  mem             Memory address
/// \param[in]  bits            Bit mask
/// \return                     Previous value
__STATIC_INLINE uint32_t os_exc_clr32 (uint32_t *mem, uint32_t bits) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
#if (__ARM_ARCH_8M_BASE__ == 1U)
    "mov   %[val],%[ret]\n"
    "bics  %[val],%[bits]\n"
#else
    "bic   %[val],%[ret],%[bits]\n"
#endif
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],Label2\n"
    "b     Label1\n"
  "Label2:\n"
  : [ret]  "=&l" (ret),
    [val]  "=&l" (val),
    [res]  "=&l" (res)
  : [mem]  "l"   (mem),
    [bits] "l"   (bits)
#if (__ARM_ARCH_8M_BASE__ == 1U)
  : "memory", "cc"
#else
  : "memory"
#endif
  );

  return ret;
}

/// Exclusive Access Operation: Check if all specified bits (32-bit) are active and clear them
/// \param[in]  mem             Memory address
/// \param[in]  bits            Bit mask
/// \return                     Active bits before clearing or 0 if not active
__STATIC_INLINE uint32_t os_exc_chk32_all (uint32_t *mem, uint32_t bits) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
#if (__ARM_ARCH_8M_BASE__ == 1U)
    "mov   %[val],%[ret]\n"
    "ands  %[val],%[bits]\n"
#else
    "and   %[val],%[ret],%[bits]\n"
#endif
    "cmp   %[val],%[bits]\n"
    "beq   Label2\n"
    "clrex\n"
    "movs  %[ret],#0\n"
    "b     L3\n"
  "Label2:\n"
#if (__ARM_ARCH_8M_BASE__ == 1U)
    "mov   %[val],%[ret]\n"
    "bics  %[val],%[bits]\n"
#else
    "bic   %[val],%[ret],%[bits]\n"
#endif
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],L3\n"
    "b     Label1\n"
  "L3:\n"
  : [ret]  "=&l" (ret),
    [val]  "=&l" (val),
    [res]  "=&l" (res)
  : [mem]  "l"   (mem),
    [bits] "l"   (bits)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Check if any specified bits (32-bit) are active and clear them
/// \param[in]  mem             Memory address
/// \param[in]  bits            Bit mask
/// \return                     Active bits before clearing or 0 if not active
__STATIC_INLINE uint32_t os_exc_chk32_any (uint32_t *mem, uint32_t bits) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
    "tst   %[ret],%[bits]\n"
    "bne   Label2\n"
    "clrex\n"
    "movs  %[ret],#0\n"
    "b     L3\n"
  "Label2:\n"
#if (__ARM_ARCH_8M_BASE__ == 1U)
    "mov   %[val],%[ret]\n"
    "bics  %[val],%[bits]\n"
#else
    "bic   %[val],%[ret],%[bits]\n"
#endif
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],L3\n"
    "b     Label1\n"
  "L3:\n"
  : [ret]  "=&l" (ret),
    [val]  "=&l" (val),
    [res]  "=&l" (res)
  : [mem]  "l"   (mem),
    [bits] "l"   (bits)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Increment (32-bit)
/// \param[in]  mem             Memory address
/// \return                     Previous value
__STATIC_INLINE uint32_t os_exc_inc32 (uint32_t *mem) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
    "adds  %[val],%[ret],#1\n"
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],Label2\n"
    "b     Label1\n"
  "Label2:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Increment (32-bit) if Less Than
/// \param[in]  mem             Memory address
/// \param[in]  max             Maximum value
/// \return                     Previous value
__STATIC_INLINE uint32_t os_exc_inc32_lt (uint32_t *mem, uint32_t max) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
    "cmp   %[max],%[ret]\n"
    "bhi    Label2\n"
    "clrex\n"
    "b      L3\n"
  "Label2:\n"
    "adds  %[val],%[ret],#1\n"
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],L3\n"
    "b     Label1\n"
  "L3:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem),
    [max] "l"   (max)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Increment (16-bit) if Less Than
/// \param[in]  mem             Memory address
/// \param[in]  max             Maximum value
/// \return                     Previous value
__STATIC_INLINE uint16_t os_exc_inc16_lt (uint16_t *mem, uint16_t max) {
  register uint32_t val, res;
  register uint16_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrexh %[ret],[%[mem]]\n"
    "cmp    %[max],%[ret]\n"
    "bhi    Label2\n"
    "clrex\n"
    "b      L3\n"
  "Label2:\n"
    "adds   %[val],%[ret],#1\n"
    "strexh %[res],%[val],[%[mem]]\n"
    "cbz    %[res],L3\n"
    "b      Label1\n"
  "L3:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem),
    [max] "l"   (max)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Increment (16-bit) and clear on Limit
/// \param[in]  mem             Memory address
/// \param[in]  max             Maximum value
/// \return                     Previous value
__STATIC_INLINE uint16_t os_exc_inc16_lim (uint16_t *mem, uint16_t lim) {
  register uint32_t val, res;
  register uint16_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrexh %[ret],[%[mem]]\n"
    "adds   %[val],%[ret],#1\n"
    "cmp    %[lim],%[val]\n"
    "bhi    Label2\n"
    "movs   %[val],#0\n"
  "Label2:\n"
    "strexh %[res],%[val],[%[mem]]\n"
    "cbz    %[res],L3\n"
    "b      Label1\n"
  "L3:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem),
    [lim] "l"   (lim)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Decrement (32-bit) if Not Zero
/// \param[in]  mem             Memory address
/// \return                     Previous value
__STATIC_INLINE uint32_t os_exc_dec32_nz (uint32_t *mem) {
  register uint32_t val, res;
  register uint32_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[mem]]\n"
    "cbnz  %[ret],Label2\n"
    "clrex\n"
    "b     L3\n"
  "Label2:\n"
    "subs  %[val],%[ret],#1\n"
    "strex %[res],%[val],[%[mem]]\n"
    "cbz   %[res],L3\n"
    "b     Label1\n"
  "L3:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Decrement (16-bit) if Not Zero
/// \param[in]  mem             Memory address
/// \return                     Previous value
__STATIC_INLINE uint16_t os_exc_dec16_nz (uint16_t *mem) {
  register uint32_t val, res;
  register uint16_t ret;

  __ASM volatile (
  "Label1:\n"
    "ldrexh %[ret],[%[mem]]\n"
    "cbnz   %[ret],Label2\n"
    "clrex\n"
    "b      L3\n"
  "Label2:\n"
    "subs   %[val],%[ret],#1\n"
    "strexh %[res],%[val],[%[mem]]\n"
    "cbz    %[res],L3\n"
    "b      Label1\n"
  "L3:\n"
  : [ret] "=&l" (ret),
    [val] "=&l" (val),
    [res] "=&l" (res)
  : [mem] "l"   (mem)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Link Get
/// \param[in]  root            Root address
/// \return                     Link
__STATIC_INLINE void *os_exc_link_get (void **root) {
  register uint32_t val, res;
  register void    *ret;

  __ASM volatile (
  "Label1:\n"
    "ldrex %[ret],[%[root]]\n"
    "cbnz  %[ret],Label2\n"
    "clrex\n"
    "b     L3\n"
  "Label2:\n"
    "ldr   %[val],[%[ret]]\n"
    "strex %[res],%[val],[%[root]]\n"
    "cbz   %[res],L3\n"
    "b     Label1\n"
  "L3:\n"
  : [ret]  "=&l" (ret),
    [val]  "=&l" (val),
    [res]  "=&l" (res)
  : [root] "l"   (root)
  : "cc", "memory"
  );

  return ret;
}

/// Exclusive Access Operation: Link Put
/// \param[in]  root            Root address
/// \param[in]  lnk             Link
__STATIC_INLINE void os_exc_link_put (void **root, void *link) {
  register uint32_t val1, val2, res;

  __ASM volatile (
  "Label1:\n"
    "ldr   %[val1],[%[root]]\n"
    "str   %[val1],[%[link]]\n"
    "dmb\n"
    "ldrex %[val1],[%[root]]\n"
    "ldr   %[val2],[%[link]]\n"
    "cmp   %[val2],%[val2]\n"
    "bne   Label1\n"
    "strex %[res],%[link],[%[root]]\n"
    "cbz   %[res],Label2\n"
    "b     Label1\n"
  "Label2:\n"
  : [val1] "=&l" (val1),
    [val2] "=&l" (val2),
    [res]  "=&l" (res)
  : [root] "l"   (root),
    [link] "l"   (link)
  : "cc", "memory"
  );
}

#endif  // (__EXCLUSIVE_ACCESS == 1U)

#pragma diag_default=Pe550

#endif  // CORE_CM_H_
