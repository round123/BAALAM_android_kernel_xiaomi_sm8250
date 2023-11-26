#!/system/bin/sh

chmod 755 /vendor/bin/thermal-engine
chmod 644 /vendor/etc/thermal-engine*

#setprop persist.sys.scrollingcache 1

killall -9 android.process.media
killall -9 mediaserver

#echo "N" > /sys/kernel/debug/debug_enabled
#echo "1" > /sys/module/subsystem_restart/parameters/disable_restart_work
#echo "0 0 0 0" > /proc/sys/kernel/printk
#echo "128" > /proc/sys/net/core/netdev_max_backlog
#echo 1 > /sys/module/printk/parameters/console_suspend
#echo 3000 > /proc/sys/vm/dirty_expire_centisecs
#echo 0 > /d/tracing/tracing_on
#echo 0 > /d/tracing/events/ext4/enable
#echo 0 > /d/tracing/events/f2fs/enable
#echo 0 > /d/tracing/events/block/enable
#setprop profiler.force_disable_ulog true
#setprop profiler.force_disable_err_rpt true
#setprop profiler.force_disable_err_rpt 1
#setprop profiler.force_disable_ulog 1
#setprop debugtool.anrhistory 0
#setprop profiler.debugmonitor false
#setprop profiler.launch false
#setprop profiler.hung.dumpdobugreport false
#setprop ro.config.htc.nocheckin 1
#setprop profiler.force_disable_ulog 1
#setprop pm.sleep_mode 1 
#setprop ro.ril.disable.power.collapse 0 
#setprop profiler.force_disable_err_rpt 1 
#setprop dalvik.vm.checkjni false 
#setprop dalvik.vm.execution-mode int:jit
#setprop ro.ril.power_collapse 1
#setprop power_supply.wakeup enable
#setprop ro.mot.eri.losalert.delay 1000
#setprop ro.config.hw_power_saving true
#setprop ro.ril.sensor.sleep.control 1
#setprop wifi.supplicant_scan_interval=300
#setprop debug.kill_allocating_task 0
#setprop ro.config.hw_fast_dormancy 1
#setprop ro.config.nocheckin 1
#setprop windowsmgr.max_events_per_sec 150
#setprop sys.use_fifo_ui 1
#setprop persist.radio.add_power_save 1
#setprop debug.composition.type c2d
#setprop video.accelerate.hw 1
#setprop debug.egl.hw 1
#setprop ro.product.gpu.driver 1
#setprop debug.enabletr true
#setprop debug.sf.hw 1
#setprop dev.pm.dyn_samplingrate 1
#setprop hwui.disable_vsync true
#setprop hwui.render_dirty_regions false
#setprop persist.sys.composition.type c2d
#setprop ro.config.enable.hw_accel true
#setprop ro.vold.umsdirtyratio 50
#setprop ro.sf.compbypass.enable 0
#setprop debug.cpurend.vsync false
#setprop ro.treble.enabled false
setprop nogravity.helper f3

# Already commented the echo
#for i in $(find /sys/ -name debug_mask); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name debug_level); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name edac_mc_log_ce); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name edac_mc_log_ue); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name enable_event_log); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name log_ecn_error); do
#echo "0" > $i;
#done
#for i in $(find /sys/ -name snapshot_crashdumper); do
#echo "0" > $i;
#done
#if [ -e /sys/module/logger/parameters/log_mode ]; then
# echo "2" > /sys/module/logger/parameters/log_mode
#fi;
#for i in $(find /sys/ -name debug_level); do
# echo "0" > $i;
#done
#for i in $(find /sys/ -name edac_mc_log_ce); do
# echo "0" > $i;
#done
#for i in $(find /sys/ -name edac_mc_log_ue); do
# echo "0" > $i;
#done
#for i in $(find /sys/ -name enable_event_log); do
# echo "0" > $i;
#done
#for i in $(find /sys/ -name log_ecn_error); do
# echo "0" > $i;
#done
#for i in $(find /sys/ -name snapshot_crashdumper); do
# echo "0" > $i;
#done


sleep 15

echo 10 > /sys/class/thermal/thermal_message/sconfig
echo 10 > /sys/module/thermal_sys/parameters/lock_sconfig
echo 1 > /sys/module/thermal_sys/parameters/lock_enable

stop vendor.power-hal-aidl && start vendor.power-hal-aidl

#echo Y > /sys/module/lpm_levels/parameters/cluster_use_deepest_state
#echo Y > /sys/module/lpm_levels/parameters/sleep_disabled

swapoff /dev/block/zram0

fstrim /data;
fstrim /cache;
fstrim /system;