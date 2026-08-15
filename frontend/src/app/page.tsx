import AuthGate from "../components/auth/AuthGate";
import Workspace from "../components/workspace/Workspace";

export default function Home() {
  return (
    <AuthGate>
      <Workspace />
    </AuthGate>
  );
}
