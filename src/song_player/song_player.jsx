import React, { useState, useEffect } from 'react';
import ReactPlayer from 'react-player';

const SongPlayer = () => {
    const [speechRecognition, setSpeechRecognition] = useState(null);
    const [isPlaying, setIsPlaying] = useState(false);

    useEffect(() => {
        // Initialize speech recognition
        const recognition = new window.webkitSpeechRecognition();
        recognition.continuous = true;
        recognition.interimResults = false;
        recognition.lang = 'de-AT';

        // Start listening for voice commands
        recognition.onstart = () => {
            console.log('Voice recognition started');
        };

        // Process recognized speech
        recognition.onresult = (event) => {
            const transcript = event.results[event.results.length - 1][0].transcript.toLowerCase();
            console.log('Recognized speech:', transcript);

            // Check for voice commands
            if (transcript.includes('spielen') || transcript.includes('start')){
                console.log('Playing song');
                setIsPlaying(true);
            } else if (transcript.includes('pause') || transcript.includes('stop')) {
                console.log('Stopping song');
                setIsPlaying(false);
            } else if (transcript.includes('vor')) {
                console.log('Skipping forward');
                skipForward(transcript);
            } else if (transcript.includes('zurück')) {
                console.log('Skipping backward');
                skipBackward(transcript);
            }
        };

        // Set speech recognition instance
        setSpeechRecognition(recognition);

        // Start speech recognition
        recognition.start();

        // Clean up on component unmount
        return () => {
            recognition.stop();
        };
    }, []);

    const handleTogglePlay = () => {
        setIsPlaying(!isPlaying);
    };

    const skipForward = (transcript) => {
        // Get the ReactPlayer instance
        const player = document.querySelector('audio');

        // Extract the number of seconds to skip from the transcript
        const secondsToSkip = parseInt(transcript.match(/\d+/)[0]) || 5;

        // Skip forward the specified number of seconds
        player.currentTime += secondsToSkip;
    };

    const skipBackward = (transcript) => {
        // Get the ReactPlayer instance
        const player = document.querySelector('audio');

        // Extract the number of seconds to skip from the transcript
        const secondsToSkip = parseInt(transcript.match(/\d+/)[0]) || 5;

        // Skip backward the specified number of seconds
        player.currentTime -= secondsToSkip;
    };

    return (
        <div>
            <ReactPlayer url="https://files.catbox.moe/jycu22.mp3" playing={isPlaying} />
            <div>
                <button onClick={() => skipForward('')}>-5s</button>
                <button onClick={handleTogglePlay}>{isPlaying ? 'Stop' : 'Start'}</button>
                <button onClick={() => skipBackward('')}>+5s</button>
            </div>
        </div>
    );
};

export default SongPlayer;
