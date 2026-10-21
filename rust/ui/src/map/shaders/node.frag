#version 300 es
precision highp float;
precision highp int;
precision highp usampler2D;
uniform usampler2D u_state;
uniform int u_state_width;
uniform bool u_active;
uniform float u_hover;
uniform float u_selected;
uniform vec3 u_colors[6];
uniform vec3 u_bg;
uniform vec3 u_fill;
uniform vec3 u_accent;
uniform vec3 u_shape;
in vec2 v_local;
flat in int v_id;
flat in int v_color;
flat in float v_dash;
out vec4 color;
void main() {
  bool hot=u_active && texelFetch(u_state,ivec2(v_id%u_state_width,v_id/u_state_width),0).r!=0u;
  bool hover=float(v_id)==u_hover;
  float width=float(v_id)==u_selected?3.5:(hover?2.6:(hot?2.2:1.6));
  vec2 q=abs(v_local-u_shape.xy*0.5)-u_shape.xy*0.5+9.0;
  float d=length(max(q,0.0))+min(max(q.x,q.y),0.0)-9.0;
  float aa=max(fwidth(d),0.01);
  float outer=1.0-smoothstep(width*0.5-aa,width*0.5+aa,d);
  if(outer<=0.0)discard;
  float inner=1.0-smoothstep(-width*0.5-aa,-width*0.5+aa,d);
  vec3 border=u_colors[v_color];
  vec3 fill=mix(u_fill,hover?u_accent:border,hover?0.18:(hot?0.10:0.0));
  if(v_dash>0.0 && inner<0.5) {
    float along=(v_local.y<4.0||v_local.y>u_shape.y-4.0)?v_local.x:v_local.y;
    float period=v_dash==2.0?5.0:7.0;
    if(mod(along,period)>(v_dash==2.0?2.0:4.0))discard;
  }
  vec3 rgb=mix(border,fill,inner);
  if(u_active&&!hot)rgb=mix(u_bg,rgb,0.22);
  color=vec4(rgb,outer);
}
