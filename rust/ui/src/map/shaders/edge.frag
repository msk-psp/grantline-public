#version 300 es
precision highp float;
precision highp int;
uniform vec3 u_colors[6];
uniform vec3 u_bg;
in float v_side;
in float v_along;
flat in int v_color;
flat in float v_strength;
flat in float v_dash;
out vec4 color;
void main(){
  if(v_dash>0.0&&mod(v_along,v_dash==1.0?5.0:9.0)>(v_dash==1.0?2.0:5.0))discard;
  color=vec4(mix(u_bg,u_colors[v_color],v_strength),1.0-smoothstep(0.65,1.0,abs(v_side)));
}
