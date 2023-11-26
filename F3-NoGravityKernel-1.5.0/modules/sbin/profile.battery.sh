#!/system/bin/sh

# SILVER Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
echo "300000" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
echo "300000" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_lp
echo "300000" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_lp
echo "1708800" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
##echo 500 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/up_rate_limit_us
##echo 10000 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/down_rate_limit_us
##echo 0 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/iowait_boost_enable
echo 0 > /sys/devices/system/cpu/cpu0/cpufreq/schedutil/exp_util

# GOLD Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor
echo "710400" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq
echo "710400" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_perf
echo "710400" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_hp
echo "825600" > /sys/devices/system/cpu/cpu4/cpufreq/scaling_max_freq
#echo 500 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/up_rate_limit_us
#echo 10000 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/down_rate_limit_us
#echo 0 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/iowait_boost_enable
echo 0 > /sys/devices/system/cpu/cpu4/cpufreq/schedutil/exp_util

# PRIME Cluster
echo "schedutil" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_governor
echo "844800" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_min_freq
echo "844800" > /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_pp
echo "844800" > /sys/module/cpu_input_boost/parameters/cpu_freq_idle_pp
echo "1075200" > /sys/devices/system/cpu/cpu7/cpufreq/scaling_max_freq
##echo 500 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/up_rate_limit_us
##echo 10000 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/down_rate_limit_us
##echo 0 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/iowait_boost_enable
echo 0 > /sys/devices/system/cpu/cpu7/cpufreq/schedutil/exp_util

#Dynamic Schedtune Boost
echo "300000" > /sys/module/cpu_input_boost/parameters/input_boost_freq_lp
echo "710400" > /sys/module/cpu_input_boost/parameters/input_boost_freq_hp
echo "844800" > /sys/module/cpu_input_boost/parameters/input_boost_freq_pp
echo "300000" > /sys/module/cpu_input_boost/parameters/max_boost_freq_lp
echo "710400" > /sys/module/cpu_input_boost/parameters/max_boost_freq_hp
echo "844800" > /sys/module/cpu_input_boost/parameters/max_boost_freq_pp
echo 0 > /sys/module/cpu_input_boost/parameters/input_boost_duration
echo 0 > /sys/module/cpu_input_boost/parameters/wake_boost_duration
#echo 0 > /sys/module/cpu_input_boost/parameters/dynamic_stune_boost_duration
#echo 0 > /sys/module/cpu_input_boost/parameters/dynamic_stune_boost

#Schedtune
#echo 0 > /dev/stune/top-app/schedtune.sched_boost
#echo 0 > /dev/stune/top-app/schedtune.sched_boost_enabled
echo 0 > /dev/stune/top-app/schedtune.prefer_idle
echo 1 > /dev/stune/top-app/schedtune.boost
echo 0 > /dev/stune/foreground/schedtune.prefer_idle
echo 0 > /dev/stune/foreground/schedtune.boost
echo -10 > /dev/stune/background/schedtune.boost
echo 0 > /dev/stune/schedtune.prefer_idle

#IO Scheduler
#echo "zen" > /sys/block/mmcblk0/queue/scheduler
#echo "zen" > /sys/block/sda/queue/scheduler
#echo "zen" > /sys/block/sdb/queue/scheduler
#echo "zen" > /sys/block/sdc/queue/scheduler
#echo "zen" > /sys/block/sdd/queue/scheduler
#echo "zen" > /sys/block/sde/queue/scheduler
#echo "zen" > /sys/block/sdf/queue/scheduler

#GPU
echo "305" > /sys/class/kgsl/kgsl-3d0/max_clock_mhz
echo "305000000" > /sys/class/kgsl/kgsl-3d0/devfreq/max_freq
echo "305000000" > /sys/class/kgsl/kgsl-3d0/max_gpuclk
echo "150" > /sys/class/kgsl/kgsl-3d0/min_clock_mhz
echo "150000000" > /sys/class/kgsl/kgsl-3d0/devfreq/min_freq
echo "150000000" > /sys/class/kgsl/kgsl-3d0/min_gpuclk
echo "0" > /sys/class/kgsl/kgsl-3d0/devfreq/adrenoboost
echo "1" > /sys/class/kgsl/kgsl-3d0/throttling
echo 1 > /sys/class/kgsl/kgsl-3d0/bus_split
echo 0 > /sys/class/kgsl/kgsl-3d0/force_bus_on
echo 0 > /sys/class/kgsl/kgsl-3d0/force_rail_on
echo 0 > /sys/class/kgsl/kgsl-3d0/force_clk_on

#LKM
#echo "18432,23040,27648,32256,85296,120640" > /sys/module/lowmemorykiller/parameters/minfree