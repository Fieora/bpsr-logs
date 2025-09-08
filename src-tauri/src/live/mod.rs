mod test_state;

use crate::live::test_state::TestState;
use crate::packets::opcodes::Pkt;
use crate::packets::packet_capture::start_capture;
use anyhow::Result;
use bpsr_protobuf::blueprotobuf;
use log::{info, warn};
use prost::Message;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

pub fn start(app_handle: AppHandle) -> Result<()> {
    let rx = match start_capture() {
        Ok(rx) => rx,
        Err(e) => {
            warn!("Error starting capture: {}", e);
            return Ok(());
        }
    };

    let mut state = TestState::new(app_handle.clone());

    let mut my_uuid: i64 = 0;
    let mut process_aoi_sync_delta = |aoi_sync_delta: blueprotobuf::AoiSyncDelta| -> Option<()> {
        let target_uuid = aoi_sync_delta.uuid.unwrap_or_default() >> 16;

        let skill_effect = aoi_sync_delta.skill_effects?;
        for sync_damage_info in skill_effect.damages {
            let value = sync_damage_info.value;
            let lucky_value = sync_damage_info.lucky_value;

            // Combine both options and continue if none exist
            let damage: i64 = match value.or(lucky_value) {
                Some(dmg) => dmg,
                None => continue, // skip this iteration
            };
            let attacker_uuid = sync_damage_info
                .top_summoner_id
                .or(sync_damage_info.attacker_uuid)
                .unwrap_or_default()
                >> 16;

            // clone

            info!(
                "UUID {:?} to UUID {:?} did {:?} damage",
                attacker_uuid, target_uuid, damage
            );

            #[derive(Serialize, Deserialize, Clone)]
            #[serde(rename_all = "camelCase")]
            struct DmgDealt {
                attacker_uuid: i64,
                target_uuid: i64,
                damage: i64,
            }

            state.on_damage(damage);
            app_handle
                .emit(
                    "damage-dealt",
                    DmgDealt {
                        attacker_uuid,
                        target_uuid,
                        damage,
                    },
                )
                .unwrap();
            app_handle
                .emit(
                    "total-damage-dealt",
                    state.encounter.my_total_damage,
                )
                .unwrap();
        }
        Some(())
    };

    while let Ok((op, data, src_server)) = rx.recv() {
        match op {
            Pkt::SyncNearEntities => {
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
            }
            Pkt::DataNotifySyncContainerData => {
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
            }
            Pkt::SyncContainerDirtyData => {
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
            }
            Pkt::SyncServerTime => {
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
            }
            Pkt::SyncToMeDeltaInfo => {
                info!("Received NotifyMsg with opcode {:?} from server {:?}", op, src_server);
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
                let sync_to_me_delta_info =
                    blueprotobuf::SyncToMeDeltaInfo::decode(bytes::Bytes::from(data))?;
                let aoi_sync_to_me_delta = sync_to_me_delta_info.delta_info.unwrap_or_default();
                let other_uuid = aoi_sync_to_me_delta.uuid.unwrap_or_default();
                if my_uuid == 0 || my_uuid != other_uuid {
                    info!("my uuid {:?}, uid: {:?}", other_uuid, other_uuid >> 16);
                    my_uuid = other_uuid;
                }

                if let Some(base_delta) = aoi_sync_to_me_delta.base_delta {
                    process_aoi_sync_delta(base_delta);
                }
            }
            Pkt::SyncNearDeltaInfo => {
                info!("Received NotifyMsg with opcode {:?} from server {:?}", op, src_server);
                // info!("Received NotifyMsg with opcode {:?} and data {:?}", op, data);
                let sync_near_delta_info =
                    blueprotobuf::SyncNearDeltaInfo::decode(bytes::Bytes::from(data))?;
                let aoi_sync_delta_vec = sync_near_delta_info.delta_infos;
                for aoi_sync_delta in aoi_sync_delta_vec {
                    process_aoi_sync_delta(aoi_sync_delta);
                }
            }
        }
    }
    Ok(())
}
