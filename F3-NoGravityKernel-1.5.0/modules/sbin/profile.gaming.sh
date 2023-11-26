#!/system/bin/sh

# SILVER Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
echo "1708800" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
echo "1708800" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_lp
echo "300000" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_lp
echo "1804800" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
##echo 0 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/up_rate_limit_us
##echo 20000 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/down_rate_limit_us
##echo 0 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/iowait_boost_enable
echo 1 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/exp_util

# GOLD Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor
echo "825600" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq
echo "825600" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_perf
echo "710400" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_hp
echo "2419200" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_max_freq
##echo 0 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/up_rate_limit_us
##echo 20000 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/down_rate_limit_us
##echo 0 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/iowait_boost_enable
echo 1 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/exp_util

# PRIME Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_governor
echo "1075200" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_min_freq
echo "1075200" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_pp
echo "844800" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_pp
echo "3187200" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_max_freq
##echo 0 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/up_rate_limit_us
##echo 20000 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/down_rate_limit_us
##echo 0 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/iowait_boost_enable
echo 1 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/exp_util

#Dynamic Schedtune Boost
echo "1708800" > /sys/module/cpu_input_boost/parameters/input_boost_freq_lp
echo "1286400" > /sys/module/cpu_input_boost/parameters/input_boost_freq_hp
echo "1190400" > /sys/module/cpu_input_boost/parameters/input_boost_freq_pp
echo "1804800" > /sys/module/cpu_input_boost/parameters/max_boost_freq_lp
echo "2419200" > /sys/module/cpu_input_boost/parameters/max_boost_freq_hp
echo "3187200" > /sys/module/cpu_input_boost/parameters/max_boost_freq_pp
echo 256 > /sys/module/cpu_input_boost/parameters/input_boost_duration
echo 1000 > /sys/module/cpu_input_boost/parameters/wake_boost_duration
#echo 1500 > /sys/module/cpu_input_boost/parameters/dynamic_stune_boost_duration
#echo 15 > /sys/module/cpu_input_boost/parameters/dynamic_stune_boost

#Schedtune
#echo 0 > /dev/stune/top-app/schedtune.sched_boost
#echo 0 > /dev/stune/top-app/schedtune.sched_boost_enabled
echo 1 > /dev/stune/top-app/schedtune.prefer_idle
echo 15 > /dev/stune/top-app/schedtune.boost
echo 1 > /dev/stune/foreground/schedtune.prefer_idle
echo 1 > /dev/stune/foreground/schedtune.boost
echo -10 > /dev/stune/background/schedtune.boost
echo 1 > /dev/stune/schedtune.prefer_idle

#IO Scheduler
#echo "deadline" > /sys/block/mmcblk0/queue/scheduler
#echo "deadline" > /sys/block/sda/queue/scheduler
#echo "deadline" > /sys/block/sdb/queue/scheduler
#echo "deadline" > /sys/block/sdc/queue/scheduler
#echo "deadline" > /sys/block/sdd/queue/scheduler
#echo "deadline" > /sys/block/sde/queue/scheduler
#echo "deadline" > /sys/block/sdf/queue/scheduler

#GPU
echo "682" > /sys/class/kgsl/kgsl-3d0/max_clock_mhz
echo "682000000" > /sys/class/kgsl/kgsl-3d0/devfreq/max_freq
echo "682000000" > /sys/class/kgsl/kgsl-3d0/max_gpuclk
echo "400" > /sys/class/kgsl/kgsl-3d0/min_clock_mhz
echo "400000000" > /sys/class/kgsl/kgsl-3d0/devfreq/min_freq
echo "400000000" > /sys/class/kgsl/kgsl-3d0/min_gpuclk
echo "2" > /sys/class/kgsl/kgsl-3d0/devfreq/adrenoboost
echo "0" > /sys/class/kgsl/kgsl-3d0/throttling
echo 0 > /sys/class/kgsl/kgsl-3d0/bus_split
echo 1 > /sys/class/kgsl/kgsl-3d0/force_bus_on
echo 1 > /sys/class/kgsl/kgsl-3d0/force_rail_on
echo 1 > /sys/class/kgsl/kgsl-3d0/force_clk_on

#LMK
#echo "33792,45056,56320,123904,168960,180224" > /sys/module/lowmemorykiller/parameters/minfree
