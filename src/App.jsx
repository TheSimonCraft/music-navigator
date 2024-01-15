import { useState } from 'react'
import './App.css'
import SongSelector from './song_selector/song_selector.jsx'
import SongPlayer from './song_player/song_player.jsx'
import Login from './login_system/login.jsx'

function App() {
  const [selectedSong, setSelectedSong] = useState(null);

  const handleSongSelect = (song) => {
    setSelectedSong(song);
  };

  return (
    <>
      <div className="app">
        <Login/>
        <div className="login-spacer"></div>
        <SongSelector onSongSelect={handleSongSelect} />
        {selectedSong && <p>Selected Song: {selectedSong}</p>}
        <SongPlayer />
      </div>
    </>
  );
}

export default App