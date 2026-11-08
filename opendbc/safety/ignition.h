#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "opendbc/safety/can.h"
#include "opendbc/safety/helpers.h"

bool ignition_can = false;
uint32_t ignition_can_cnt = 0U;

void ignition_can_hook(const CANPacket_t *msg) {
  // GM Global B: CGM power mode on vehicle CAN2 or CAN8, mapped to Panda bus 0.
  // This receive-only detector also runs before the host selects a car safety mode.
  if (msg_matches(msg, 0x370U, 0U, 6U) && (msg->extended == 0U)) {
    static uint8_t gm_mode = 0xFFU;
    static uint8_t gm_freshness = 0xFFU;
    static uint8_t gm_samples = 0U;
    uint8_t mode = (msg->data[4] >> 5U) & 0x7U;
    uint8_t freshness = msg->data[3] & 0x1FU;
    if (ignition_can_cnt > 2U) {
      gm_mode = 0xFFU;
      gm_freshness = 0xFFU;
      gm_samples = 0U;
    }
    // Undefined modes and duplicate counters do not keep ignition alive.
    // PowerModeGate is not an ignition-validity bit: propulsion can have gate=0.
    if ((mode <= 4U) && (freshness != gm_freshness)) {
      gm_samples = (mode == gm_mode) ? (uint8_t)(gm_samples + (gm_samples < 4U ? 1U : 0U)) : 1U;
      gm_mode = mode;
      gm_freshness = freshness;
      ignition_can_cnt = 0U;
      // Two samples to wake; four Off samples to avoid a transient shutdown.
      if (gm_samples >= (mode == 0U ? 4U : 2U)) {
        ignition_can = mode != 0U;
      }
    }
    return;
  }

  // GM exception
  if (msg_matches(msg, 0x1F1U, 0U, 8U)) {
    // SystemPowerMode (2=Run, 3=Crank Request)
    ignition_can = (msg->data[0] & 0x2U) != 0U;
    ignition_can_cnt = 0U;
  }

  // Rivian R1S/T GEN1 exception
  if (msg_matches(msg, 0x152U, 0U, 8U)) {
    // 0x152 overlaps with Subaru pre-global which has this bit as the high beam
    int counter = msg->data[1] & 0xFU;  // max is only 14

    static int prev_counter_rivian = -1;
    if ((counter == ((prev_counter_rivian + 1) % 15)) && (prev_counter_rivian != -1)) {
      // VDM_OutputSignals->VDM_EpasPowerMode
      ignition_can = ((msg->data[7] >> 4U) & 0x3U) == 1U;  // VDM_EpasPowerMode_Drive_On=1
      ignition_can_cnt = 0U;
    }
    prev_counter_rivian = counter;
  }

  // Tesla Model 3/Y exception
  if (msg_matches(msg, 0x221U, 0U, 8U)) {
    // 0x221 overlaps with Rivian which has random data on byte 0
    int counter = msg->data[6] >> 4;

    static int prev_counter_tesla = -1;
    if ((counter == ((prev_counter_tesla + 1) % 16)) && (prev_counter_tesla != -1)) {
      // VCFRONT_LVPowerState->VCFRONT_vehiclePowerState
      int power_state = (msg->data[0] >> 5U) & 0x3U;
      ignition_can = power_state == 0x3;  // VEHICLE_POWER_STATE_DRIVE=3
      ignition_can_cnt = 0U;
    }
    prev_counter_tesla = counter;
  }

  // Mazda exception
  if (msg_matches(msg, 0x9EU, 0U, 8U)) {
    ignition_can = (msg->data[0] >> 5) == 0x6U;
    ignition_can_cnt = 0U;
  }

  // Volkswagen MEB exception
  if (msg_matches(msg, 0x3C0U, 0U, 4U)) {
    int counter = msg->data[1] & 0xFU;

    static int prev_counter_vw_meb = -1;
    if ((counter == ((prev_counter_vw_meb + 1) % 16)) && (prev_counter_vw_meb != -1)) {
      // Klemmen_Status_01->ZAS_Kl_15
      ignition_can = ((msg->data[2] >> 1) & 1U) != 0U;
      ignition_can_cnt = 0U;
    }
    prev_counter_vw_meb = counter;
  }

  // TODO: this is too loose, Teslas have 0x222
  // body v2 exception
  // if (((msg->bus == 0U) || (msg->bus == 2U)) && (msg->addr == 0x222U)) {
  //   ignition_can = true;
  //   ignition_can_cnt = 0U;
  // }
}
