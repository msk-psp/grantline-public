pub const LANGUAGES: [&str; 4] = ["en", "ko", "ja", "zh-CN"];
const MESSAGES: &[(&str, [&str; 3])] = &[
    ("Expanded", ["펼침", "展開済み", "已展开"]),
    ("Collapsed", ["접힘", "折りたたみ", "已折叠"]),
    (
        "Map unavailable. Use Accounts or Resources.",
        [
            "권한 맵을 표시할 수 없습니다. 계정 또는 리소스 화면을 이용하세요.",
            "マップを表示できません。アカウントまたはリソース画面をご利用ください。",
            "无法显示权限图。请使用账户或资源页面。",
        ],
    ),
    (
        "Enable JavaScript to explore the map.",
        [
            "권한 맵을 탐색하려면 JavaScript를 켜세요.",
            "マップを操作するには JavaScript を有効にしてください。",
            "请启用 JavaScript 以浏览权限图。",
        ],
    ),
    (
        "Arrow keys: navigate nodes. Enter: select or expand. Home/End: first/last node. Page Up/Down: pan.",
        [
            "방향키: 노드 이동. Enter: 선택 또는 펼치기. Home/End: 처음·마지막 노드. Page Up/Down: 화면 이동.",
            "矢印キー: ノード移動。Enter: 選択・展開。Home/End: 最初・最後のノード。Page Up/Down: 画面移動。",
            "方向键：切换节点。Enter：选择或展开。Home/End：首个或末个节点。Page Up/Down：移动视图。",
        ],
    ),
    (
        "Observation scope and limitations",
        ["관측 범위와 제한", "観測範囲と制限", "观测范围与限制"],
    ),
    (
        "Excluded by configuration",
        ["설정상 관측 제외", "設定による除外", "配置排除"],
    ),
    (
        "Unsupported privilege semantics",
        [
            "권한 해석 지원 범위 밖",
            "権限の解釈が未対応",
            "尚不支持此权限语义",
        ],
    ),
    ("Read failed", ["조회 실패", "読み取り失敗", "读取失败"]),
    (
        "Partially observed",
        ["일부 관측됨", "一部観測済み", "部分已观测"],
    ),
    (
        "Some permissions could not be read; affected access is unknown.",
        [
            "일부 권한을 읽지 못했습니다. 해당 범위의 접근 여부는 알 수 없습니다.",
            "一部の権限を読み取れませんでした。対象範囲のアクセスは不明です。",
            "部分权限读取失败，相关范围的访问状态未知。",
        ],
    ),
    (
        "Requested permissions could not be verified; no changes are planned for them.",
        [
            "요청한 권한 중 확인하지 못한 항목은 변경 계획에서 제외됩니다.",
            "確認できない要求権限は変更計画から除外されます。",
            "无法验证的请求权限不会纳入变更计划。",
        ],
    ),
    (
        "Excluded or unsupported permissions remain unknown. Other observed permissions are still shown.",
        [
            "관측 제외·미지원 범위는 접근 여부를 확정하지 않습니다. 확인한 다른 권한은 계속 표시합니다.",
            "除外・未対応の範囲はアクセス不明です。その他の観測済み権限は引き続き表示します。",
            "排除或尚不支持的范围保持未知，其他已观测权限仍会显示。",
        ],
    ),
    ("Access routes", ["접근 경로", "アクセス経路", "访问路径"]),
    (
        "Inherited grants",
        ["상속된 권한", "継承された権限", "继承权限"],
    ),
    ("From", ["비교 시작", "比較元", "起始"]),
    ("To", ["비교 종료", "比較先", "结束"]),
    ("Compare", ["비교", "比較", "比较"]),
    ("Visible again", ["다시 관측됨", "再び可視", "恢复可见"]),
    ("Unknown now", ["현재 관측 불가", "現在不明", "当前未知"]),
    (
        "Declared bridges describe a credential hop; they are not a measured login.",
        [
            "선언된 브리지는 자격 증명 전달 경로이며 실제 로그인 검증 결과는 아닙니다.",
            "宣言されたブリッジは認証情報の経路であり、実際のログイン検証ではありません。",
            "声明的桥接表示凭据路径，并非实际登录验证结果。",
        ],
    ),
    ("Users", ["사용자", "ユーザー", "用户"]),
    (
        "Service accounts",
        ["서비스 계정", "サービスアカウント", "服务账户"],
    ),
    ("Roles", ["역할", "ロール", "角色"]),
    ("Groups", ["그룹", "グループ", "组"]),
    ("Policies", ["정책", "ポリシー", "策略"]),
    (
        "Resources in",
        ["리소스가 있는 서비스", "リソースのサービス", "资源所在服务"],
    ),
    (
        "Service instances",
        ["서비스 인스턴스", "サービスインスタンス", "服务实例"],
    ),
    ("View", ["보기", "表示", "视图"]),
    ("Zoom in", ["확대", "拡大", "放大"]),
    ("Zoom out", ["축소", "縮小", "缩小"]),
    ("Fit view", ["전체 보기", "全体表示", "全景"]),
    ("Read", ["읽기", "読み取り", "读取"]),
    ("Write", ["쓰기", "書き込み", "写入"]),
    ("Admin", ["관리자", "管理者", "管理"]),
    (
        "Click to follow · scroll to zoom · Shift+scroll to pan · drag to pan · Esc to reset",
        [
            "클릭: 경로 추적 · 스크롤: 확대/축소 · Shift+스크롤: 상하 이동 · 드래그: 이동 · Esc: 초기화",
            "クリック: 経路追跡 · スクロール: 拡大縮小 · Shift+スクロール: 上下移動 · ドラッグ: 移動 · Esc: リセット",
            "点击追踪路径 · 滚动缩放 · Shift+滚动上下移动 · 拖动平移 · Esc 重置",
        ],
    ),
    (
        "Archived; request a new review",
        [
            "이전 기록 · 새 검토 필요",
            "アーカイブ・再申請が必要",
            "归档记录，需重新申请",
        ],
    ),
    (
        "Visibility changes",
        ["관측 범위 변화", "可視性の変化", "可见性变化"],
    ),
    ("Review", ["검토", "レビュー", "审阅"]),
    (
        "Loading catalog…",
        [
            "권한 정보를 읽는 중…",
            "権限情報を読み込み中…",
            "正在读取权限信息…",
        ],
    ),
    (
        "Untangle access. Follow the grants.",
        [
            "접근 경로를 풀고, 권한의 근거를 따라가세요.",
            "アクセスを整理し、権限の根拠をたどる。",
            "理清访问路径，追溯权限来源。",
        ],
    ),
    ("Map", ["권한 맵", "権限マップ", "权限图"]),
    ("Accounts", ["계정", "アカウント", "账户"]),
    ("Resources", ["리소스", "リソース", "资源"]),
    ("Services", ["서비스", "サービス", "服务"]),
    ("Matrix", ["권한 표", "権限表", "权限矩阵"]),
    ("Changes", ["변경 사항", "変更", "变更"]),
    ("History", ["기록", "履歴", "历史"]),
    ("Approvals", ["승인 요청", "承認申請", "审批请求"]),
    ("Request access", ["권한 요청", "権限を申請", "申请权限"]),
    ("Sign in", ["로그인", "ログイン", "登录"]),
    ("Sign out", ["로그아웃", "ログアウト", "退出登录"]),
    (
        "Explore the console",
        ["콘솔 둘러보기", "コンソールを見る", "浏览控制台"],
    ),
    ("Read only", ["읽기 전용", "読み取り専用", "只读"]),
    ("Authenticated", ["인증됨", "認証済み", "已认证"]),
    ("Theme", ["테마 전환", "テーマ切替", "切换主题"]),
    ("Language", ["언어", "言語", "语言"]),
    ("Search", ["검색", "検索", "搜索"]),
    ("Filter", ["필터", "絞り込み", "筛选"]),
    (
        "All services",
        ["모든 서비스", "すべてのサービス", "所有服务"],
    ),
    (
        "All environments",
        ["모든 환경", "すべての環境", "所有环境"],
    ),
    ("Principals", ["계정·주체", "プリンシパル", "主体"]),
    (
        "Roles and policies",
        ["역할·정책", "ロールとポリシー", "角色和策略"],
    ),
    ("Clear selection", ["선택 해제", "選択解除", "清除选择"]),
    (
        "Hover or focus a resource to follow its access routes.",
        [
            "리소스에 마우스를 올리거나 초점을 맞추면 접근 경로가 강조됩니다.",
            "リソースにカーソルまたはフォーカスを合わせるとアクセス経路が強調されます。",
            "悬停或聚焦资源可高亮其访问路径。",
        ],
    ),
    (
        "Access is unknown for unread services.",
        [
            "읽지 못한 서비스의 접근 권한은 알 수 없습니다.",
            "読み取れないサービスのアクセス権限は不明です。",
            "无法读取的服务访问权限未知。",
        ],
    ),
    (
        "Interactive bundle unavailable; build the UI to enable interactions.",
        [
            "대화형 파일이 없습니다. UI를 빌드하면 상호작용을 사용할 수 있습니다.",
            "対話用ファイルがありません。UIをビルドしてください。",
            "缺少交互资源，请构建界面。",
        ],
    ),
    ("Observed", ["관측됨", "観測済み", "已观测"]),
    ("Declared", ["선언됨", "宣言済み", "已声明"]),
    ("Unknown", ["알 수 없음", "不明", "未知"]),
    ("Subject", ["대상 계정", "対象アカウント", "目标账户"]),
    ("Resource", ["리소스", "リソース", "资源"]),
    ("Service", ["서비스", "サービス", "服务"]),
    ("Privilege", ["권한", "権限", "权限"]),
    (
        "Recent changes (days)",
        ["최근 변경 일수", "最近の変更日数", "近期变更天数"],
    ),
    (
        "Observed change routes",
        ["관측된 변경 경로", "観測した変更経路", "观测到的变更路径"],
    ),
    (
        "Complete observation window",
        ["비교 기준 관측 있음", "基準となる観測あり", "存在基准观测"],
    ),
    (
        "Incomplete observation window",
        [
            "기간 이전 관측이 없어 일부 변경만 확인 가능",
            "期間前の観測がなく一部の変更のみ確認可能",
            "缺少期间之前的观测，仅能确认部分变更",
        ],
    ),
    ("Source", ["권한 출처", "権限の出所", "权限来源"]),
    ("Grantor", ["부여자", "付与者", "授予者"]),
    ("Child resources", ["하위 리소스", "下位リソース", "子资源"]),
    ("View details", ["상세 보기", "詳細を見る", "查看详情"]),
    ("Action", ["작업", "操作", "操作"]),
    ("Grant", ["부여", "付与", "授予"]),
    ("Revoke", ["회수", "取消", "撤销"]),
    (
        "No results",
        ["결과가 없습니다", "結果がありません", "暂无结果"],
    ),
    ("Direct grants", ["직접 권한", "直接権限", "直接权限"]),
    ("Findings", ["진단", "診断", "诊断"]),
    ("Information", ["정보", "情報", "信息"]),
    ("Warning", ["주의", "警告", "警告"]),
    ("Error", ["오류", "エラー", "错误"]),
    (
        "No findings",
        ["진단 항목이 없습니다", "診断項目はありません", "暂无诊断"],
    ),
    (
        "Observed grants",
        ["관측된 권한", "観測された権限", "观测权限"],
    ),
    (
        "Declared grants",
        ["선언된 권한", "宣言された権限", "声明权限"],
    ),
    (
        "No changes",
        ["변경할 사항이 없습니다", "変更はありません", "无需变更"],
    ),
    (
        "Command unavailable",
        [
            "명령을 만들 수 없습니다",
            "コマンドを生成できません",
            "无法生成命令",
        ],
    ),
    (
        "Preview only; no permission has been applied.",
        [
            "미리보기입니다. 실제 권한은 적용하지 않았습니다.",
            "プレビューです。実際の権限は適用していません。",
            "仅为预览，尚未应用实际权限。",
        ],
    ),
    (
        "Record snapshot",
        ["스냅샷 기록", "スナップショットを記録", "记录快照"],
    ),
    ("Snapshots", ["스냅샷", "スナップショット", "快照"]),
    ("Time", ["시각", "日時", "时间"]),
    ("Added", ["추가", "追加", "新增"]),
    ("Removed", ["제거", "削除", "移除"]),
    (
        "No baseline",
        ["비교 기준 없음", "比較基準なし", "无比较基准"],
    ),
    ("Requests", ["요청", "申請", "请求"]),
    ("Requester", ["요청자", "申請者", "申请人"]),
    (
        "Required approvers",
        ["필수 승인자", "必要な承認者", "必需审批人"],
    ),
    ("Status", ["상태", "状態", "状态"]),
    ("Pending", ["승인 대기", "承認待ち", "待审批"]),
    ("Approved", ["승인 완료", "承認済み", "已批准"]),
    ("Denied", ["거부됨", "却下", "已拒绝"]),
    ("PR created", ["PR 생성됨", "PR作成済み", "PR已创建"]),
    ("Publishing", ["PR 생성 중", "PR作成中", "正在创建PR"]),
    (
        "Needs inspection",
        ["상태 확인 필요", "状態確認が必要", "需要核查"],
    ),
    ("Approve", ["승인", "承認", "批准"]),
    ("Deny", ["거부", "却下", "拒绝"]),
    ("Create PR", ["PR 생성", "PRを作成", "创建PR"]),
    ("Open PR", ["PR 열기", "PRを開く", "打开PR"]),
    ("Submit request", ["요청 제출", "申請を送信", "提交请求"]),
    ("Before", ["변경 전", "変更前", "变更前"]),
    ("After", ["변경 후", "変更後", "变更后"]),
    (
        "Plan fingerprint",
        ["변경 계획 식별값", "変更計画の識別値", "变更计划标识"],
    ),
    (
        "Approval and PR creation do not apply IAM permissions.",
        [
            "승인과 PR 생성만으로 IAM 권한이 적용되지는 않습니다.",
            "承認とPR作成だけではIAM権限は適用されません。",
            "审批和创建PR不会直接应用IAM权限。",
        ],
    ),
    (
        "Configure authenticated approvals and a code writer to request changes.",
        [
            "인증·승인자·코드 작성 연동을 설정하면 변경을 요청할 수 있습니다.",
            "認証・承認者・コード連携を設定すると変更を申請できます。",
            "配置认证、审批人和代码集成后即可申请变更。",
        ],
    ),
    ("Working…", ["처리 중…", "処理中…", "处理中…"]),
    ("Refresh", ["새로고침", "更新", "刷新"]),
    (
        "Catalog unavailable; access is unknown.",
        [
            "서비스를 읽지 못했습니다. 접근 권한은 알 수 없습니다.",
            "サービスを読み取れません。アクセス権限は不明です。",
            "无法读取服务，访问权限未知。",
        ],
    ),
    (
        "Rows are limited; narrow the filter to see more.",
        [
            "표시 수를 제한했습니다. 필터를 좁혀 확인하세요.",
            "表示件数を制限しました。絞り込みを指定してください。",
            "显示数量受限，请缩小筛选范围。",
        ],
    ),
];
pub fn tr(lang: &str, key: &str) -> String {
    let index = match lang {
        "ko" => Some(0),
        "ja" => Some(1),
        "zh-CN" => Some(2),
        _ => None,
    };
    index
        .and_then(|i| {
            MESSAGES
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, values)| values[i])
        })
        .unwrap_or(key)
        .into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_label_has_four_complete_catalogs() {
        for (key, values) in MESSAGES {
            assert!(!key.is_empty());
            for v in values {
                assert!(!v.is_empty());
            }
            for lang in LANGUAGES {
                assert!(!tr(lang, key).is_empty());
            }
        }
    }
}
