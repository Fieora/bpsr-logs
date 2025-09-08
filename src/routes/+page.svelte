<script lang="ts">
    import { listen } from '@tauri-apps/api/event';

    let dmgDealtTo: string = $state("not found");
    let totalDmg: string = $state("not found");

    type DamageEvent = {
        attackerUuid: number;
        targetUuid: number;
        damage: number;
    };

    listen<DamageEvent>('damage-dealt', (event) => {
        const t = event.payload;
        console.log(t.attackerUuid)
        dmgDealtTo = `Current: UID ${t.attackerUuid} to UID ${t.targetUuid}: damage ${t.damage}`
    });

    listen<Number>('total-damage-dealt', (event) => {
        totalDmg = `total dmg: ${event.payload}`;
    });
</script>

<main class="container">
    <h1>DPS Meter</h1>
    <p>{dmgDealtTo}</p>
    <p>{totalDmg}</p>
</main>
