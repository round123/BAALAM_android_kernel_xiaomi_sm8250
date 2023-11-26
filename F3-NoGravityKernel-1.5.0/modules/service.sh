#!/system/bin/sh

# nogravity initialization script

   # boottime stune
   echo "1" > /dev/stune/schedtune.prefer_idle
   echo "100" > /dev/stune/schedtune.boost

   chmod 644 /sys/class/thermal/thermal_message/sconfig
   chmod 644 /sys/module/thermal_sys/parameters/lock_value
   chmod 644 /sys/module/thermal_sys/parameters/lock_sconfig

   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/schedutil/up_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/schedutil/down_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/schedutil/iowait_boost_enable
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/schedutil/exp_util
   chmod 644 /sys/devices/system/cpu/cpu0/cpufreq/schedutil/hispeed_freq

   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/scaling_min_freq
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/scaling_max_freq
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/schedutil/up_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/schedutil/down_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/schedutil/iowait_boost_enable
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/schedutil/exp_util
   chmod 644 /sys/devices/system/cpu/cpu4/cpufreq/schedutil/hispeed_freq

   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/scaling_governor
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/scaling_min_freq
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/scaling_max_freq
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/schedutil/up_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/schedutil/down_rate_limit_us
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/schedutil/iowait_boost_enable
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/schedutil/exp_util
   chmod 644 /sys/devices/system/cpu/cpu7/cpufreq/schedutil/hispeed_freq

   chmod 644 /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_lp
   chmod 644 /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_perf
   chmod 644 /sys/module/cpu_input_boost/parameters/remove_input_boost_freq_pp
   chmod 644 /sys/module/cpu_input_boost/parameters/cpu_freq_idle_lp
   chmod 644 /sys/module/cpu_input_boost/parameters/cpu_freq_idle_hp
   chmod 644 /sys/module/cpu_input_boost/parameters/cpu_freq_idle_pp
   chmod 644 /sys/module/cpu_input_boost/parameters/input_boost_freq_lp
   chmod 644 /sys/module/cpu_input_boost/parameters/input_boost_freq_hp
   chmod 644 /sys/module/cpu_input_boost/parameters/input_boost_freq_pp
   chmod 644 /sys/module/cpu_input_boost/parameters/input_boost_duration
   chmod 644 /sys/module/cpu_input_boost/parameters/dynamic_stune_boost_duration
   chmod 644 /sys/module/cpu_input_boost/parameters/dynamic_stune_boost

   chmod 644 /sys/class/kgsl/kgsl-3d0/devfreq/max_pwrlevel
   chmod 644 /sys/class/kgsl/kgsl-3d0/devfreq/min_freq
   chmod 644 /sys/class/kgsl/kgsl-3d0/min_gpuclk
   chmod 644 /sys/class/kgsl/kgsl-3d0/devfreq/max_freq
   chmod 644 /sys/class/kgsl/kgsl-3d0/max_gpuclk
   chmod 644 /sys/class/kgsl/kgsl-3d0/devfreq/adrenoboost
   chmod 644 /sys/class/kgsl/kgsl-3d0/throttling
   chmod 644 /sys/class/kgsl/kgsl-3d0/bus_split
   chmod 644 /sys/class/kgsl/kgsl-3d0/force_bus_on
   chmod 644 /sys/class/kgsl/kgsl-3d0/force_rail_on
   chmod 644 /sys/class/kgsl/kgsl-3d0/force_clk_on

   chmod 644 /dev/cpuset/top-app/cpus
   chmod 644 /dev/cpuset/foreground/cpus
   chmod 644 /dev/cpuset/background/cpus
   chmod 644 /dev/cpuset/system-background/cpus
   chmod 644 /dev/cpuset/restricted/cpus

   # according to Qcom this legacy value improves first launch latencies
   # stock value is 512k
   # from franciscofranco
   setprop dalvik.vm.heapminfree 2m

   # Fast Charge
#   write /sys/kernel/fast_charge/force_fast_charge 1

   # Reset stune
   echo "0" > /dev/stune/schedtune.prefer_idle
   echo "0" > /dev/stune/schedtune.boost

   #Schedtune
#   write /dev/stune/top-app/schedtune.prefer_idle 1
#   write /dev/stune/top-app/schedtune.boost 1
#   write /dev/stune/foreground/schedtune.prefer_idle 1
#   write /dev/stune/foreground/schedtune.boost 0
#   write /dev/stune/background/schedtune.boost -10

#   write 8136 > /sys/class/devfreq/soc:qcom,cpu-llcc-ddr-bw/max_freq
#   write 15258 > /sys/class/devfreq/soc:qcom,cpu-cpu-llcc-bw/max_freq

   # No Gravity Kernel App & Spectrum profiles setup
   # Set default profile on first boot
   setprop persist.spectrum.profile p0
   # Enable Spectrum support
   setprop spectrum.support 1
   # Add kernel name
   setprop persist.spectrum.kernel NoGravity

   # No Gravity Kernel App & Spectrum profiles setup
   # Set default profile on first boot
   setprop persist.spectrum.profile p0
   # Enable Spectrum support
   setprop spectrum.support 1
   # Add kernel name
   setprop persist.spectrum.kernel NoGravity

   # To be used only for exclusive.sh commands
   cd / && ./date/adb/modules/kernelsu-helper/sbin/init.special_power.sh
   
   cd / && ./date/adb/modules/kernelsu-helper/sbin/profile.balance.sh

#add MIUI camera flag
#on property:sys.camera.miui.apk=*
#    setprop vendor.camera.miui.apk ${sys.camera.miui.apk}
   