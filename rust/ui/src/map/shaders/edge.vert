#version 300 es
precision highp float;
precision highp int;
precision highp usampler2D;
layout(location=0) in vec2 a_vertex;
layout(location=1) in vec4 a_endpoints;
layout(location=2) in vec4 a_data;
uniform vec3 u_camera;
uniform vec2 u_view;
uniform vec3 u_shape;
uniform usampler2D u_state;
uniform int u_state_width;
uniform bool u_active;
out float v_side;
out float v_along;
flat out int v_color;
flat out float v_strength;
flat out float v_dash;
bool isLit(int id){return texelFetch(u_state,ivec2(id%u_state_width,id/u_state_width),0).r!=0u;}
vec2 cubic(vec2 a,vec2 b,vec2 c,vec2 d,float t){float s=1.0-t;return s*s*s*a+3.0*s*s*t*b+3.0*s*t*t*c+t*t*t*d;}
vec2 point(float t){
  vec2 from=a_endpoints.xy,to=a_endpoints.zw;
  bool back=to.x<from.x;
  vec2 p=from+vec2(back?0.0:u_shape.x,u_shape.y*0.5);
  vec2 q=to+vec2(back?u_shape.x+7.0:-7.0,u_shape.y*0.5);
  if(abs(to.x-from.x-u_shape.z)<0.5){float m=(p.x+q.x)*0.5;return cubic(p,vec2(m,p.y),vec2(m,q.y),q,t);}
  float r=back?-40.0:40.0;float a=p.x+r,b=q.x-r;
  if(t<0.4)return cubic(p,vec2(a,p.y),vec2(a,40.0),vec2(a+r,40.0),t/0.4);
  if(t<0.6)return mix(vec2(a+r,40.0),vec2(b-r,40.0),(t-0.4)/0.2);
  return cubic(vec2(b-r,40.0),vec2(b,40.0),vec2(b,q.y),q,(t-0.6)/0.4);
}
void main(){
  bool hot=u_active&&isLit(int(a_data.x))&&isLit(int(a_data.y));
  float t=min(a_vertex.x,1.0);
  vec2 p=point(t),tangent=normalize(point(min(t+0.0005,1.0))-point(max(t-0.0005,0.0))+vec2(0.000001));
  vec2 normal=vec2(-tangent.y,tangent.x);
  float width=max(0.6,(hot?2.2:(a_data.w==2.0?1.8:1.2))*u_camera.x);
  p=p*u_camera.x+u_camera.yz;
  if(a_vertex.x>1.5){if(a_vertex.y!=0.0)p+=(-tangent*8.0+normal*a_vertex.y*3.5)*u_camera.x;v_side=0.0;}
  else{p+=normal*a_vertex.y*width*0.5;v_side=a_vertex.y;}
  gl_Position=vec4(p/u_view*vec2(2.0,-2.0)+vec2(-1.0,1.0),0.0,1.0);
  v_color=int(a_data.z);v_strength=hot?1.0:(u_active?0.05:0.34);v_dash=a_vertex.x>1.5?0.0:a_data.w;
  v_along=t*length(a_endpoints.xy-a_endpoints.zw);
}
